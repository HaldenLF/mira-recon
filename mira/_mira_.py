import argparse
import re
import logging

from modules.WebsiteAnalyzer import WebsiteAnalyzer
from modules.utils import strip_protocol
from modules.DomainInfo import DomainInfo
from modules.WebScanner import WebScanner
from modules.PortScanner import PortScanner

logging.basicConfig(level=logging.INFO, format='%(message)s')


def main():
    parser = argparse.ArgumentParser(description="Mira, a reconnaissance tool")
    parser.add_argument('-bi', '--basic-info', action='store_true', help="Basic Target Information")
    parser.add_argument('-ps', '--port-scan', action='store_true', help="Port Scan")
    parser.add_argument('-ds', '--dir-scan', action='store_true', help="Directory Scan")
    parser.add_argument('-ss', '--sub-scan', action='store_true', help="Subdomain Scan")
    parser.add_argument('-ts', '--tech-scan', action='store_true', help="Technology Scan")
    parser.add_argument('-t', '--target', type=str, help="Target URL", required=True)
    parser.add_argument('-p', '--ports', type=str, help="Ports to scan (e.g., 1-1024 or 22,80,443)")
    parser.add_argument('-wl', '--wordlist', type=str, help="Path to the wordlist", default="subdomains.txt")
    
    args = parser.parse_args()

    if args.target:
        pattern = re.compile(r"^(https?://)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+)$")
        match = pattern.match(args.target)
        
        if match:
            target = match.group(0)
            if not target.startswith("http"):
                target = "http://" + target
        else:
            logging.error("Invalid URL. Please enter a valid URL.")
            return
    else:
        logging.error("Please enter a target URL.")
        return
        
    if args.basic_info:
        try:
            analyse = DomainInfo.dns_look_up(target)
            if analyse:
                info = analyse.get_domain_info()
                logging.info(info)
            else:
                logging.error("Failed to perform DNS lookup.")
        except Exception as e:      
            logging.error(f"An error occurred during basic scan: {e}")

    elif args.port_scan:
        try:
            scan = PortScanner(target, args.ports)
            results = scan.basic_scan()
            for result in results:
                logging.info(result)
        except Exception as e:
            logging.error(f"An error occurred during port scan: {e}")

    elif args.dir_scan:
        try:
            scanner = WebScanner(target, args.wordlist)
            directories = scanner.scan_directories()
            if directories:
                logging.info("Directories found:")
                for directory in directories:
                    logging.info(directory)
            else:
                logging.info("No directories found.")
        except Exception as e:
            logging.error(f"An error occurred during directory scan: {e}")
    
    elif args.sub_scan:
        try:
            scanner = WebScanner(target, args.wordlist)    
            subdomains = scanner.scan_subdomains()
            if subdomains:
                logging.info("Subdomains found:")
                for subdomain in subdomains:
                    logging.info(subdomain)
            else:
                logging.info("No subdomains found.")
        except Exception as e:
            logging.error(f"An error occurred during subdomain scan: {e}")

    elif args.tech_scan:
        try:
            analyzer = WebsiteAnalyzer(target)
            results = analyzer.analyze()
        except Exception as e:    
            logging.error(f"An error occurred during technology scan: {e}")


if __name__ == "__main__":
    main()