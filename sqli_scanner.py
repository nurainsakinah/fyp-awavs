from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from colorama import Fore, init

init(autoreset=True)

sql_str_true = '\' or 1=1 and 1=1;#'
sql_str_false = '\' or 1=1 and 1=2;#'

class sqli_scanner:
    def __init__(self, session):
        self.session = session
        self.count_sqli = 0

    def extract_forms(self, url):
        try:
            response = self.session.get(url)
        except requests.exceptions.ConnectionError:
            print(Fore.RED + '[***] Could not connect to the application. Check the Internet connection and'
                             ' Target Application status')
            exit()
        except requests.exceptions.InvalidSchema:
            print(Fore.RED + '[***] Error in the format of the provided URL')
            exit()
        parsed_html = BeautifulSoup(response.content, 'html.parser')
        return parsed_html.findAll("form")

    def submit_form(self, post_url, method, post_data):
        try:
            if method == 'post':
                return self.session.post(post_url, data=post_data)
            else:
                return self.session.get(post_url, params=post_data)
        except requests.exceptions.ConnectionError:
            print(Fore.RED + '[***] Could not connect to the application. Check the Internet connection and'
                             ' Target Application status')
            exit()
        except requests.exceptions.InvalidSchema:
            print(Fore.RED + '[***] Error in the format of the provided URL')
            exit()

    def is_resp_equal(self, resp1, resp2):
        if resp1.status_code != resp2.status_code:
            return False
        if str(resp1.content) != str(resp2.content):
            return False
        return True

    def run_sqli_test(self, link):
        print("\n[+] Testing forms in " + link + " for SQLI\n")
        forms = self.extract_forms(link)
        count = 0
        form_count = 0
        for form in forms:
            iteration = 1
            action = form.get("action")
            post_url = urljoin(link, action)
            method = form.get("method")
            post_data_true = {}
            post_data_false = {}
            resp_true = None
            resp_false = None
            while iteration <= 2:
                curr_form = None
                if iteration == 2:
                    new_forms = self.extract_forms(link)
                    curr_form = new_forms[form_count]
                else:
                    curr_form = form
                inputs_list = curr_form.findAll('input')
                for inputs in inputs_list:
                    name = inputs.get('name')
                    value = inputs.get('value')
                    input_type = inputs.get('type')
                    if input_type == 'text':
                        post_data_true[name] = sql_str_true
                        post_data_false[name] = sql_str_false
                    else:
                        post_data_true[name] = value
                        post_data_false[name] = value
                if iteration == 1:
                    resp_true = self.submit_form(post_url, method, post_data_true)
                else:
                    resp_false = self.submit_form(post_url, method, post_data_false)
                iteration += 1

            if not self.is_resp_equal(resp_true, resp_false):
                count += 1
                print(Fore.RED + '\n[***] The following form in the link ' + link + ' is vulnerable to SQL Injection.'
                                                                                    ' Security Risk: Severe.\n')
                print(form)
            form_count += 1
        if count == 0:
            print('\n[+] The link is not vulnerable to SQL Injection.\n')
            return 0
        else:
            self.count_sqli += count
            return count
