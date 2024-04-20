import requests
from urllib3.exceptions import InsecureRequestWarning
import json
import ssl
from requests.exceptions import SSLError

from sql_module import *



def discover_webpage(target, port=80):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # disable the SSL warning

    r = requests.get(f'http://{target}/', verify=False, allow_redirects=True)

    #print(r)
    
    if r != "<Response [404]": #If the page is not 404d
        #print("Alive")
        check_self_sign(r)
        update_table("hosts", "host", target, "isAlive", 1)
        res = r.text
        print(f"Found: {r.url}")
        print("Adding login URL to table...")
        update_table("hosts", "host", target, "URL", r.url)
        return (res)
        #print(find_parameters(res))
        
# Function to check for self-signed or invalid SSL cert
def check_self_sign(response):
    try:
        cert_data = ssl.get_server_certificate((response.url, 443))
        x509 = ssl.PEM_cert_to_DER_cert(cert_data)
        x509 = ssl.DER_cert_to_x509(x509)
        issuer = x509.get_issuer()
        subject = x509.get_subject()
        if issuer == subject:
          print("Self-Signed SSL Certificate Detected!")  
    except SSLError as e:
        return {'is_self_signed': False, 'valid': False, 'error': str(e)}
    except Exception as e:
        print(f"Error checking certificate: {e}")


# r = requests.get('https://192.168.56.110/cgi-bin/luci', verify=False, allow_redirects=True)
# print(r.text)

# _data = 'luci_username=root&luci_password=iotgoathardcodedpassword'
# r = requests.post('https://192.168.56.110/cgi-bin/luci', data=_data, verify=False)
# print(r)
#Get the service name
#Query for default credentials
#Test them

#luci_username=duh&luci_password=duhs
