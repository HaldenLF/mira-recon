import nmap
import logging
from .utils import strip_protocol

class PortScanner:
    def __init__(self, target, ports):
        self.target = strip_protocol(target)
        self.ports = ports
        self.result = []  

    def basic_scan(self):
        logging.info(f"Performing basic port scan on {self.target} for common ports...")
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments=f'-p {self.ports}')
            self.scan_results(nm)
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        return self.result

    def scan_results(self, nm):
        try:
            for host in nm.all_hosts():
                self.result.append(f'Host: {host} ({nm[host].hostname()})')
                self.result.append(f'State: {nm[host].state()}')
                for proto in nm[host].all_protocols():
                    self.result.append(f'Protocol: {proto}')
                    for port in nm[host][proto].keys():
                        self.result.append(f'Port: {port}, State: {nm[host][proto][port]["state"]}')
        except Exception as e:
            logging.error(f"An error occurred: {e}")
