import argparse
import re
import logging

from .modules.WebsiteAnalyzer import WebsiteAnalyzer
from .modules.DomainInfo import DomainInfo
from .modules.WebScanner import WebScanner
from .modules.PortScanner import PortScanner

logging.basicConfig(level=logging.INFO, format='%(message)s')

class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        help_message = """/////////////////////////////////////////////////////////////////////////////////////////
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
-----------------------------------------------------------------------------------------
Welcome to Mira!
        
This reconnaissance tool helps with the initial phase of information gathering.

It can perform DNS lookups, port scans, directory scans, subdomain scans, and technology scans.

Please use the following options to perform the desired scan.
=========================================================================================
Note: The target URL and one other option must be provided for all scans.

Options:
"""
        print(help_message)
        super().print_help()

def main():
    parser = CustomArgumentParser()
    
    parser.add_argument('-Di', '--domain-info', action='store_true', help="Domain Information")
    parser.add_argument('-Ps', '--port-scan', action='store_true', help="Port Scan")
    parser.add_argument('-Ds', '--dir-scan', action='store_true', help="Directory Scan")
    parser.add_argument('-Ss', '--sub-scan', action='store_true', help="Subdomain Scan")
    parser.add_argument('-Ts', '--tech-scan', action='store_true', help="Technology Scan")
    parser.add_argument('-t', '--target', type=str, help="Target URL", required=True)
    parser.add_argument('-p', '--ports', type=str, help="Ports to scan (e.g., 1-1024 or 22,80,443). Use with -Ps")
    parser.add_argument('-Wl', '--wordlist', type=str, help="Path/to/wordlist. Use with -Ss", default="subdomains.txt")
    
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
        
    if args.domain_info:
        try:
            analyse = DomainInfo.dns_look_up(target)
            if analyse:
                info = analyse.get_domain_info()
                logging.info(info)
            else:
                logging.error("Failed to perform DNS lookup.")
        except Exception as e:      
            logging.error(f"An error occurred during domain info scan: {e}")

    elif args.port_scan:
        try:
            scan = PortScanner(target, args.ports)
            results = scan.port_scan()
            if results:
                pass
            else:
                logging.info("No open ports found.")
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

