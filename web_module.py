import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from sql_module import *



def discover_webpage(target, port=80):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # disable the SSL warning
    r = requests.get(f'http://{target}/cgi-bin/luci', verify=False, allow_redirects=True)
    #print(r)
    if r != "<Response [404]": #If the page is not 404d
        #print("Alive")
        update_table("hosts", "host", target, "isAlive", 1)
        res = r.text
        print(f"Found: {r.url}")
        print("Adding login URL to table...")
        update_table("hosts", "host", target, "URL", r.url)
        return (res)
        #print(find_parameters(res))
        
    

# r = requests.get('https://192.168.56.110/cgi-bin/luci', verify=False, allow_redirects=True)
# print(r.text)

# _data = 'luci_username=root&luci_password=iotgoathardcodedpassword'
# r = requests.post('https://192.168.56.110/cgi-bin/luci', data=_data, verify=False)
# print(r)
#Get the service name
#Query for default credentials
#Test them

#luci_username=duh&luci_password=duhs

