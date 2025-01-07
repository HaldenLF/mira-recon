import subprocess
import builtwith

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
        lines = output.strip().split('\n')
        formatted_lines = []
        for line in lines:
            formatted_line = line.strip().replace(',', ',\n - ')
            formatted_lines.append(f" - {line.strip()}")
        return "\n".join(formatted_lines)

    def analyze(self):
        """Analyze the website and print detected technologies."""
        print("\nDetected Technologies (BuiltWith):")
        print("=================================")
        self.get_builtwith_technologies()

        print("\nDetected Technologies (WhatWeb):")
        print("===============================")
        technologies = self.get_whatweb_technologies()
        if technologies:
            formatted_technologies = self.format_output(technologies)
            print(formatted_technologies)
