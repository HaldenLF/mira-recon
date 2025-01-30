import requests
import logging

from threading import Thread, Lock
from queue import Queue
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from .utils import strip_protocol

N_THREADS = 200
print_lock = Lock()

class WebScanner:
    def __init__(self, target, wordlist):
        self.target = target
        self.Target = strip_protocol(self.target)
        self.wordlist = wordlist
        self.q = Queue()
        self.list_lock = Lock()
        self.results = []
        
    def scan_directories(self): 
        logging.info(f"Performing directory scan on {self.target}...\n")

        try:
            response = requests.get(self.target, timeout=5)
            response.raise_for_status()  
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Error accessing {self.target}: {e}")
            return self.results
        
        soup = BeautifulSoup(response.text, 'html.parser')
        directories = set()

        try:
            for link in soup.find_all('a'):
                url = link.get('href')
                if url:
                    full_url = urljoin(self.target, url)
                    parsed_url = urlparse(full_url)

                    if parsed_url.path.endswith('/'):
                        directories.add(full_url)
        except Exception as e:
            logging.error(f"An error occurred: {e}")

        self.results.extend(directories)
        return self.results
    
    def scan_subdomain(self, subdomain):
        url = f"http://{subdomain}.{self.Target}"
        try:
            requests.get(url)
        except requests.ConnectionError:
            pass
        else:
            with self.list_lock:
                self.results.append(url)

    def scan_thread(self, scan_function):
        while True:
            item = self.q.get()
            scan_function(item)
            self.q.task_done()

    def scan_subdomains(self):
        self.results.clear()
        logging.info(f"Performing subdomain scan on {self.Target}...\n"
                     "May take a while depending on the size of the wordlist...")

        with open(self.wordlist, 'r') as f:
            for subdomain in f:
                self.q.put(subdomain.strip())

        for _ in range(N_THREADS):
            worker = Thread(target=self.scan_thread, args=(self.scan_subdomain,))
            worker.daemon = True
            worker.start()

        self.q.join()
        return self.results