import requests
from threading import Thread, Lock
from queue import Queue

class SubdomainScanner:
    def __init__(self, domain, wordlist="subdomains.txt", num_threads=10):
        self.domain = domain
        self.wordlist = wordlist
        self.num_threads = num_threads
        self.q = Queue()
        self.list_lock = Lock()
        self.discovered_domains = {}  # Use a dictionary to store discovered subdomains

    def scan_subdomains(self):
        while True:
            # Get the subdomain from the queue
            subdomain = self.q.get()
            # Scan the subdomain
            url = f"http://{subdomain}.{self.domain}"
            try:
                response = requests.get(url, timeout=5)  # Add a timeout to avoid hanging
                status_code = response.status_code
            except requests.ConnectionError:
                # Skip subdomains that produce a connection error
                self.q.task_done()
                continue
            except requests.Timeout:
                # Skip subdomains that timeout
                self.q.task_done()
                continue
            except requests.RequestException:
                # Skip subdomains that produce any other request-related errors
                self.q.task_done()
                continue
            
            # Only process and store if the status code is not 404
            if status_code != 404 and "Connection Error":
                print(f"[+] Discovered subdomain: {url} (Status: {status_code})")
                # Add the subdomain and its status code to the dictionary
                with self.list_lock:
                    self.discovered_domains[url] = status_code

            # We're done with scanning that subdomain
            self.q.task_done()

    def start_scan(self):
        # Fill the queue with all the subdomains
        with open(self.wordlist) as file:
            subdomains = file.read().splitlines()
            for subdomain in subdomains:
                self.q.put(subdomain)

        # Start all threads
        for _ in range(self.num_threads):
            worker = Thread(target=self.scan_subdomains)
            worker.daemon = True
            worker.start()

        # Wait for the queue to be empty
        self.q.join()

        # Return the dictionary of discovered subdomains (already filtered)
        return self.discovered_domains

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fast Subdomain Scanner using Threads")
    parser.add_argument("domain", help="Domain to scan for subdomains without protocol (e.g without 'http://' or 'https://')")
    parser.add_argument("-l", "--wordlist", help="File that contains all subdomains to scan, line by line. Default is subdomains.txt",
                        default="subdomains.txt")
    parser.add_argument("-t", "--num-threads", help="Number of threads to use to scan the domain. Default is 10", default=10, type=int)

    args = parser.parse_args()

    scanner = SubdomainScanner(
        domain=args.domain,
        wordlist=args.wordlist,
        num_threads=args.num_threads
    )

    discovered_subdomains = scanner.start_scan()
    print("Discovered Subdomains:", discovered_subdomains)