import requests
import re
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

class Scanner:
    def __init__(self, url):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []

    def extract_links_from(self, url):
        try:
            response = self.session.get(url)
        except requests.exceptions.ConnectionError:
            print(Fore.RED + '[***] Could not connect to the application. Check the Internet connection and'
                             ' Target Application status')
            exit()
        except requests.exceptions.InvalidSchema:
            print(Fore.RED + '[***] Error in the format of the provided URL')
            exit()
        return re.findall('(?:href=")(.*?)"', str(response.content))

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urljoin(self.target_url, link)

            if '#' in link:
                link = link.split('#')[0]

            if self.target_url in link and link not in self.target_links and 'logout' not in link:
                self.target_links.append(link)
                print(Fore.CYAN + link)
                self.crawl(link)
