import subprocess
import builtwith    
import logging
import json


def format_output(output, indent=0):
    formatted_output = []
    indent_str = ' ' * indent
    if isinstance(output, dict):
        for key, value in output.items():
            if key.lower() in ["country"]:
                continue
            if isinstance(value, dict) and "string" in value:
                formatted_output.append(f"{indent_str}{key.replace('_', ' ').title()}: {', '.join(value['string'])}")
            elif isinstance(value, (dict, list)):
                formatted_output.append(f"{indent_str}{key.replace('_', ' ').title()}:")
                formatted_output.append(format_output(value, indent + 4))
            else:
                formatted_output.append(f"{indent_str}{key.replace('_', ' ').title()}: {value}")
    elif isinstance(output, list):
        for item in output:
            formatted_output.append(format_output(item, indent))
    else:
        formatted_output.append(f"{indent_str}{output}")
    return "\n".join(formatted_output)


class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = url
    
    def get_builtwith_technologies(self):
        try:
            website = builtwith.parse(self.url)
            return website
        except Exception as e:        
            logging.error(f"An error occurred while parsing with BuiltWith: {e}")
            return {}

    def get_whatweb_technologies(self):
        try:
            result = subprocess.run(['whatweb', self.url, '--log-json=-'], capture_output=True, text=True, check=True)
            if result.returncode == 0:
                if result.stdout.strip():
                    json_lines = []
                    for line in result.stdout.splitlines():
                        try:
                            json_line = json.loads(line)
                            json_lines.append(json_line)
                        except json.JSONDecodeError:
                            continue
                    return json_lines
                else:
                    logging.error("WhatWeb returned an empty response.")
                    return []
            else:
                logging.error(f"Error: {result.stderr}")
                return []
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return []

    def analyze(self):
        print("\nDetected Technology:")
        print("=================================")
        
        builtwith_technologies = self.get_builtwith_technologies()
        if builtwith_technologies:
            logging.info(format_output(builtwith_technologies))

        print("---------------------------------")
        
        whatweb_technologies = self.get_whatweb_technologies()
        if whatweb_technologies:
            for tech in whatweb_technologies:
                logging.info(format_output(tech))

        return {
            "BuiltWith": builtwith_technologies,
            "WhatWeb": whatweb_technologies
        }