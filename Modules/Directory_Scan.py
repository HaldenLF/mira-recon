import requests
from bs4 import BeautifulSoup

def find_directories(target):
    response = requests.get(target)
    soup = BeautifulSoup(response.text, 'html.parser')
    directories = []
    for link in soup.find_all('a'):
        url = link.get('href')
        if url and url.endswith('/'):
            directories.append(url)
    return directories