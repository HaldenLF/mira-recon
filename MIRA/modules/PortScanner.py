import socket
import logging
from threading import Thread, Lock
from queue import Queue
from .utils import strip_protocol

N_THREADS = 200
print_lock = Lock()

class PortScanner:
    def __init__(self, target, ports):
        self.target = strip_protocol(target)
        self.ports =  self.parse_ports(ports)
        self.results = []
        self.q = Queue()
        
    def parse_ports(self, ports):
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part.strip()))
        return port_list    

    def open_port(self, port):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((self.target, port))
        except:
            pass
        else:
            with print_lock:
                logging.info(f"{self.target:15}: {port:5} is open")
                self.results.append(port)
        finally:
            s.close()

    def scan_thread(self):
        while True:
            worker = self.q.get()
            self.open_port(worker)
            self.q.task_done()

    def port_scan(self):
        logging.info(f"Starting port scan on {self.target}")
        for t in range(N_THREADS):
            t = Thread(target=self.scan_thread)
            t.daemon = True
            t.start()
        for worker in self.ports:
            self.q.put(worker)
        self.q.join()
        logging.info("Port scan completed.\n"
                     f"Closed or filtered ports: {len(self.ports) - len(self.results)}")
        return self.results
