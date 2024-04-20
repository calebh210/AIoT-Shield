import requests
import json
import csv
from ai_module import *
from sql_module import read_column, insert_to_table
from web_module import discover_webpage
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # disable the SSL warning

def parse_textfile():
    file = open("test.txt")
    credentialPairs = []
    for line in file:
        credentials = (line.split(":")) #Add option for user defined delimiter maybe?
        credentialPairs.append(credentials)
    return credentialPairs

def parse_csv(vendor):
    credentials = []
    with open("default-passwords.csv", newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in spamreader:
            if row[0] == vendor:
                #print(', '.join(row))
                credentials.append(row[1])
                credentials.append(row[2])
    return credentials

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


def check_url_exists(url, target): # This function needs a LOT more error handling. 
    if url[0] == None:
        print("No URL found in Database, therefore this attack cannot proceed")
        print("Would you like to scan for one now? (y/n)")
        choice = input()
        if choice == "y":
            discover_webpage(target)
            return True #THIS MAY NOT ALWAYS WORK! CHECK FOR CASES WHERE THE SCAN RUNS BUT A WEBPAGE IS NOT RECOVERED
        else:
            print("Cancelling attack...")
            return False
    else:
        return True

def bruting_attack(target):

    url = read_column("URL", "host", target)

    if not check_url_exists(url, target):
        return

    print(f"Trying to login to {url[0]}")
    try:
        res = requests.get(url[0], verify=False, allow_redirects=True)
        params = get_parameters(res.text) # returns a touple of vendor, username, password
        creds = parse_csv(params[0])
        #print(creds)
        data = craft_request([params[1], params[2]], [creds[0],creds[1]])
        #print(request)
        brute_req = send_request(url[0], data)

        if brute_req.status_code == 200:
            print("Valid Login Found:")
            print(creds)
            report_defaultcreds_vuln(target, url[0], creds)
    except Exception as error:
        print("ERROR! Could not parse parameters, please try again")
        print(error)

def report_defaultcreds_vuln(host, location, credentials):
    _type = "Default Credentials"
    severity = "Due to the low complexity, this is a high-severity vulnerability"
    description = f"Default login was found to work on \"{location}\". The login was {credentials[0]}:{credentials[1]}"
    remediation = "Change the default credentials to something more secure"

    vals = (None, host, _type, severity, description, remediation)

    insert_to_table("vulns", vals)

### CANNOT RUN THIS WITHOUT FIRST RUNNING A PORT SCAN TO DISCOVER URL
### MAKE ERROR HANDLING IF BRUTE IS RUN FIRST + MAKE OPTION TO DO IT
### ADD SSH COMPATABILITY AS WELL
