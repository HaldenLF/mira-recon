#!/usr/bin/env python3

import re
import socket
import whois
import nmap
import requests
import subprocess
import builtwith
from fpdf import FPDF 
from queue import Queue
from bs4 import BeautifulSoup
from threading import Thread, Lock
from urllib.parse import urljoin, urlparse


def intro_ascii():
        print("""/////////////////////////////////////////////////////////////////////////////////////////
//             .         .                                                             //
//            ,8.       ,8.           8 8888   8 888888888o.            .8.            //
//           ,888.     ,888.          8 8888   8 8888    `88.          .888.           //
//          .`8888.   .`8888.         8 8888   8 8888     `88         :88888.          //
//         ,8.`8888. ,8.`8888.        8 8888   8 8888     ,88        . `88888.         //
//        ,8'8.`8888,8^8.`8888.       8 8888   8 8888.   ,88'       .8. `88888.        //
//       ,8' `8.`8888' `8.`8888.      8 8888   8 888888888P'       .8`8. `88888.       //
//      ,8'   `8.`88'   `8.`8888.     8 8888   8 8888`8b          .8' `8. `88888.      //
//     ,8'     `8.`'     `8.`8888.    8 8888   8 8888 `8b.       .8'   `8. `88888.     //
//    ,8'       `8        `8.`8888.   8 8888   8 8888   `8b.    .888888888. `88888.    //
//   ,8'         `         `8.`8888.  8 8888   8 8888     `88. .8'       `8. `88888.   //
//                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////
///\n///\n///\n///""")

class PDFReport(FPDF):
    
    # Set the header of the PDF report
    def header(self):
        self.set_font('Arial', 'B', 12) 
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')  
        self.ln(10) 

    # Add a chapter title in the PDF report
    def chapter_title(self, title): 
        self.set_font('Arial', 'B', 14)      
        self.cell(0, 10, title, 0, 1, 'L')   
        self.ln(5)  

    # Add the body content of a chapter in the PDF report
    def chapter_body(self, body): 
        self.set_font('Arial', '', 12)  
        self.multi_cell(0, 10, body)     
        self.ln() 

    # Add a complete report section (title + body) to the PDF report
    def add_report_section(self, title, body):
        self.chapter_title(title)
        self.chapter_body(body)

class DomainInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_whois_info(self):
        # Retrieve WHOIS information
        try:
            w = whois.whois(self.domain)
            site_name = w.name if w.name else "N/A"
            domain_name = w.domain_name if w.domain_name else self.domain
            return site_name, domain_name
        except Exception as e:
            print(f"Error retrieving WHOIS information: {e}")
            return "N/A", self.domain

    def get_ip_address(self):
        # Retrieve the IP address
        try:
            return socket.gethostbyname(self.domain)
        except Exception as e:
            print(f"Error retrieving IP address: {e}")
            return "N/A"

    def get_domain_info(self):
        #Retrieve and return all domain-related information
        site_name, domain_name = self.get_whois_info()
        ip_address = self.get_ip_address()

        return {
            "Site Name": site_name,
            "Domain Name": domain_name,
            "IP Address": ip_address,
        }

class PortScanner:
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports
        self.result = []

    def basic_scan(self):
        # Perform a basic port scan
        print(f"Performing basic port scan on {self.target} for ports: {self.ports}...")
        nm = nmap.PortScanner()
        nm.scan(self.target, arguments=f'-p {self.ports}')  # Scanning specified ports

        self._process_scan_results(nm)
        return self.result

    def advanced_scan(self):
        # Perform an advanced port scan
        print(f"Performing advanced scan on {self.target} for ports: {self.ports}...")
        nm = nmap.PortScanner()
        options = f"-sS -sV -O -A -p {self.ports}"  # Advanced scan options
        nm.scan(self.target, arguments=options)

        self._process_scan_results(nm)
        return self.result

    def _process_scan_results(self, nm):
        # Method to process and store scan results
        for host in nm.all_hosts():
            self.result.append(f'Host: {host} ({nm[host].hostname()})')
            self.result.append(f'State: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                self.result.append(f'Protocol: {proto}')
                for port in nm[host][proto].keys():
                    self.result.append(f'Port: {port}, State: {nm[host][proto][port]["state"]}')

class WebScanner:
    def __init__(self, target, wordlist):
        self.target = target
        self.wordlist = wordlist
        self.q = Queue()
        self.list_lock = Lock()
        self.results = []

    def scan_directories(self):# Scan for directories  
        self.results.clear()
        print(f"Performing directory scan on {self.target}...")

        try:
            response = requests.get(self.target, timeout=5)
            response.raise_for_status()  
        except requests.exceptions.RequestException as e:
            print(f"[!] Error accessing {self.target}: {e}")
            return self.results
        
        soup = BeautifulSoup(response.text, 'html.parser')
        directories = set()

        for link in soup.find_all('a'):
            url = link.get('href')
            if url:
                full_url = urljoin(self.target, url)
                parsed_url = urlparse(full_url)

                if parsed_url.path.endswith('/'):
                    directories.add(full_url)

        # Print and store the found directories
        for dir in directories:
            print(f"[+] Found directory: {dir}")
            self.results.append(dir)

        return self.results

    def scan_subdomains(self):
        self.results.clear()
        print(f"Performing subdomain scan on {self.target}...")
        
        q = Queue()
        self.results = []
        list_lock = Lock()
        
        with open(self.wordlist, 'r') as f:
            for subdomain in f:
                q.put(subdomain.strip())
        
        def scan():
            while True:
                subdomain = q.get()
                url = f"http://{subdomain}.{self.target}"
                
                try:
                    requests.get(url)
                except requests.ConnectionError:
                    pass
                else:
                    with list_lock:
                        self.results.append(url)
                        print(f"[+] Discovered subdomain: {url}")
                
                q.task_done()
        
        for t in range(10):
            worker = Thread(target=scan)
            worker.daemon = True
            worker.start()

        q.join()
        
        return self.results
            
class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = url

    def get_builtwith_technologies(self):
        website = builtwith.parse(self.url)
        for key, value in website.items():
            print(key + ":", ", ".join(value))

    def get_whatweb_technologies(self):
        try:
            result = subprocess.run(['whatweb', self.url], capture_output=True, text=True, check=True)
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"Error: {result.stderr}")
                return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    @staticmethod
    def format_output(output):
        pattern = r",(?![^\[\]]*\))"
        items = re.split(pattern, output)
        items = [item.strip() for item in items]
        formatted_output = "\n".join(items)
        return formatted_output


    def analyze(self):
        # Analyze website and print detected technologies
        print("\nDetected Technologies (BuiltWith):")
        print("=================================")
        self.get_builtwith_technologies()

        print("\nDetected Technologies (WhatWeb):")
        print("===============================")
        technologies = self.get_whatweb_technologies()
        if technologies:
            formatted_technologies = self.format_output(technologies)
            print(formatted_technologies)

def menu():
    while True:
        print("\n----------------------------------------------------------------------------------\n"
              "1. Full Scan and Report of target site\n"
              "2. Basic Target Information\n"
              "3. Port Scan\n"
              "4. Directory & Subdomain Scan\n"
              "5. Technology Scan\n")

        userChoice = input(">>> ")
        
        if userChoice == '1':
            "Full scan implementation"
            
        elif userChoice == '2':
            analyse = DomainInfo(target)
            info = analyse.get_domain_info()
            
            for key, value in info.items():
                print(f"{key}: {value}")
                
        elif userChoice == '3':
            while True:
                print("\nChoose a scan option:\n"
                    "1. Basic Port Scan\n"
                    "2. Advanced Scan\n"
                    "3. Exit\n")

                port_scan_choice = input(">>> ")

                if port_scan_choice == '1':
                    ports = input("Enter the ports to scan (e.g., 1-1024 or 22,80,443): ")
                    scan = PortScanner(target, ports)
                    basic_result = scan.basic_scan()
                    for result in basic_result:
                        print(result)
                elif port_scan_choice == '2':
                    ports = input("Enter the ports to scan (e.g., 1-1024 or 22,80,443): ")
                    scan = PortScanner(target, ports)
                    advanced_result = scan.advanced_scan()
                    for result in advanced_result:
                        print(result)
                elif port_scan_choice == '3':
                    break
                else:
                    print("Invalid choice. Please try again.")
                    
        elif userChoice == "4":
            wordlist = "common.txt"
            scanner = WebScanner(target, wordlist)
            
            print("----------------------------------------------------------------------------------\n"
                "1. Directory Scan\n"
                "2. Subdomain Scan\n"
                "3. Exit\n")
            
            scan_choice = input(">>> ")
            
            if scan_choice == '1':
                results = scanner.scan_directories()
            elif scan_choice == '2':
                results = scanner.scan_subdomains()
            elif scan_choice == '3':
                break
            else:
                print("Invalid choice. Please try again.")
                return
            
        elif userChoice == "5":
            print(f"Scanning {target} for used technology...")
            analyser = WebsiteAnalyzer(target)
            analyser.analyze()
            
        elif userChoice == "exit":
            print("Goodbye!")
            break
        
        else:
            print("Invalid option.Please try again.")
    
if __name__ == "__main__":
    intro_ascii()
    print("Welcome to Mira! An tool for speeding up the intial information gathering process!\n"
          "----------------------------------------------------------------------------------\n")
    userTarget = input("What is your target site?\n"
                                ">>> ")
    print(f"Retriving and storing IP address for {userTarget}...")
    # Retrieve and store target and ip_address 
    # without having to go through option 2 on menu
    analyse = DomainInfo(userTarget)
    info = analyse.get_domain_info()
    
    global target
    global ip_address
    
    target = userTarget
    ip_address = info['IP Address']
    
    print("----------------------------------------------------------------------------------\n"
          "What type of information would you like to gather?\n")
    menu()