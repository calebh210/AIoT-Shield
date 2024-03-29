#!venv/bin/python3
import nmap3
import os
import requests
from sql_module import *
from web_module import discover_webpage

nmap = nmap3.Nmap()

def scan_ports(target):
    ports = []
    results=nmap.scan_top_ports(target)
    data = (results[target]['ports'])
    for item in data:
        if item['state'] == "open":
            ports.append(item['portid'])
    # ports = [item['portid'] for item in data ]
    print(ports)
    
    update_table("hosts", "host", target, "open_ports", ports)

    if 80 or 443 in ports:
        print("Potential web ports exposed, would you like to check for a login portal?")
        discover_webpage(target)

def scan_cves(target):
    #https://services.nvd.nist.gov/rest/json/cves/2.0
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=HP")
    API_DATA = r.json()
    for key in API_DATA['vulnerabilities']:
        print(key['cve']['id']) 
    #print(API_DATA['vulnerabilities'])

    return


def discover_os(target):
    if os.getuid() != 0:
        print("Root privileges are required to run this scan!")
        return
    results=nmap.nmap_os_detection(target)
    print(results)
    return

def scan_all(target):
    scan_ports(target)
    dsicover_os(target)
