import re
import whois
import socket
import logging

class DomainInfo:
    def __init__(self, target):
        self.target = target
        self.whois_data = []

    def get_ip_address(self):
        try:
            domain = re.sub(r'^https?://', '', self.target)
            ip_address = socket.gethostbyname(domain)
            self.whois_data.append(f"IP Address: {ip_address}\n")
        except Exception as e:
            logging.error(f"IP Address: Not found\nAn error occurred during IP lookup: {e}\n")


    def whois_lookup(self):
        try:
            w = whois.whois(self.target)
            whois_info = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': w.creation_date,
                'Expiration Date': w.expiration_date,
                'Last Updated': w.updated_date,
                'DNS Servers': w.name_servers,
                'Status': w.status,
                'Emails': w.emails,
                'DNSSEC': w.dnssec,
            }
            self.whois_data.append(whois_info)
        except Exception as e:
            logging.error(f"An error occurred during WHOIS lookup: {e}")

    def format_output(self):
        try:
            formatted_data = []
            for item in self.whois_data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        formatted_data.append(f"{key}: {value}")
                else:
                    formatted_data.append(item.strip())
            return "\n".join(formatted_data)
        except Exception as e:
            logging.error(f"An error occurred when formatting the domain output: {e}")

    def get_domain_info(self):
        try:
            self.get_ip_address()
            self.whois_lookup()
            return self.format_output()
        except Exception as e:
            logging.error(f"An error occurred when retrieving domain information: {e}")

    @staticmethod
    def dns_look_up(target):
        try:
            return DomainInfo(target)
        except Exception as e:
            logging.error(f"An error occurred during DNS lookup: {e}")
