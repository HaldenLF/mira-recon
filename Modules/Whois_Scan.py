import socket
import requests
import whois
import geoip2.database

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

    def get_cloud_host_name(self, ip_address):
        """Retrieve the cloud server host name using an external API."""
        try:
            response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip={ip_address}")
            return response.json().get('isp', 'N/A')
        except Exception as e:
            print(f"Error retrieving cloud host name: {e}")
            return "N/A"

    def get_domain_info(self):
        """Retrieve and return all domain-related information."""
        site_name, domain_name = self.get_whois_info()
        ip_address = self.get_ip_address()
        cloud_host_name = self.get_cloud_host_name(ip_address)
 

        return {
            "Site Name": site_name,
            "Domain Name": domain_name,
            "IP Address": ip_address,
            "Cloud Server Host Name": cloud_host_name
        }

if __name__ == "__main__":
    domain = "example.com"  # Replace with the desired domain
    analyzer = DomainInfo(domain)
    info = analyzer.get_domain_info()

    for key, value in info.items():
        print(f"{key}: {value}")