import socket
import whois
import nmap
from fpdf import FPDF 

target = ''
ip_address = 0

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
/////////////////////////////////////////////////////////////////////////////////////////\n///\n///\n///\n///""")

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
        """Retrieve WHOIS information for the domain."""
        try:
            w = whois.whois(self.domain)
            site_name = w.name if w.name else "N/A"
            domain_name = w.domain_name if w.domain_name else self.domain
            return site_name, domain_name
        except Exception as e:
            print(f"Error retrieving WHOIS information: {e}")
            return "N/A", self.domain

    def get_ip_address(self):
        """Retrieve the IP address of the domain."""
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



def main():
    print("What type of information would you like to gather?\n"
          "1. Full Scan and Report of target site\n"
          "2. Basic Target Information\n"
          "3. Port Scan\n"
          "4. Directory & Subdomain Scan\n"
          "5. Technology Scan\n")

    userChoice = input(">>> \n")
    
    if userChoice == '1':
        "Full scan implementation"
        
    if userChoice == '2':
        analyse = DomainInfo(target)
        info = analyse.get_domain_info()
        
        for key, value in info.items():
            print(f"{key}: {value}")
            
    if userChoice == '3':
        while True:
            print("\nChoose a scan option:")
            print("1. Open Port Scan")
            print("2. Advanced Scan")
            print("3. Exit")

            port_scan_choice = input("Enter your choice (1/2/3): ")

            if port_scan_choice == '1':
                ports = input("Enter the ports to scan (e.g., 1-1024 or 22,80,443): ")
                scan = PortScanner(target, ports)
                basic_result = scan.basic_scan(target, ports)
                for result in basic_result:
                    print(result)
            elif port_scan_choice == '2':
                ports = input("Enter the ports to scan (e.g., 1-1024 or 22,80,443): ")
                scan = PortScanner(target, ports)
                advanced_result = scan.advanced_scan(target, ports)
                for result in advanced_result:
                    print(result)
            elif port_scan_choice == '3':
                print("Back to main")
                main()
            else:
                print("Invalid choice. Please try again.")
    
    
if __name__ == "__main__":
    intro_ascii()
    print("Welcome to Mira! An tool for speeding up the intial information gathering process!\n"
          "----------------------------------------------------------------------------------\n")
    target = userTarget = input("What is your target site?\n"
                                ">>> \n")
    main()