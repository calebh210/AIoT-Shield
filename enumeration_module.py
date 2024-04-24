#!.venv/bin/python3
import nmap3
import os
import requests
from ai_module import cve_lookup
from sql_module import *
from web_module import discover_webpage
from ftplib import FTP

nmap = nmap3.Nmap()

def scan_ports(target):
    ports = []
    results=nmap.scan_top_ports(target)
    data = (results[target]['ports'])
    for item in data:
        if item['state'] == "open":
            ports.append(item['portid'])
    # ports = [item['portid'] for item in data ]
    
    if ports == []:
        print(f"No open ports found!")
        return

    print(f"Open ports found: {ports}")
    
    update_table("hosts", "host", target, "open_ports", ports)

    if "80" in ports or "443" in ports:
        print("Potential web ports exposed, checking for login portal...")
        discover_webpage(target)
    
    if "21" in ports:
        check_ftp(target)
        
def scan_cves(target):
    cve_list = []
    services = discover_services(target)
    if services is not []:
        #print(services)
        for service in services:
            #https://services.nvd.nist.gov/rest/json/cves/2.0
            r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}")

            # This try catch block prevents crashes in case of a null response
            try:
                API_DATA = r.json()
                for key in API_DATA['vulnerabilities']:
                    cve_list.append(key['cve']['id']) 
            except:
                pass
        f = open(f"{target}-cves.txt","w")
        f.write(str(cve_list))
        f.close()

        try:
            update_table("hosts", "host", target, "CVEs", f"CVEs saved to {target}-cves.txt") # put the location of the txt in the database
        except:
            pass

        print(f"CVEs saved to {target}-cves.txt")

        print("Would you like to also do an AI based CVE detection? (y/n)") ## optional module incase the NIST API isnt working
        resp = input()
        if resp == "y":
            ai_cves = cve_lookup(services)
            print(ai_cves)
            f = open(f"{target}-cves.txt","a")
            f.write(str(ai_cves))
            f.close()
            print(f"AI CVEs saved to {target}-cves.txt")
        else:
            pass

        return


def discover_os(target):
    if os.getuid() != 0:
        print("Root privileges are required to run this scan!")
        return
    results=nmap.nmap_os_detection(target)
    try:
        print(results[target]['osmatch'][0]['name'])
        OS = results[target]['osmatch'][0]['name']
        update_table("hosts", "host", target, "OS", results[target]['osmatch'][0]['name'])
    except Exception as error:
        print("ERROR: Are you sure that the host is alive?")
        print(error)
    return

def scan_all(target):
    scan_ports(target)
    dsicover_os(target)
    discover_services(target)

def discover_services(target):
    services = []
    try:
        version_result = nmap.nmap_version_detection(target)
        for ports in version_result[target]['ports']:
            
            #print((ports['service']['product']))
            if 'product' in ports['service']:
                services.append(ports['service']['product'])
            else:
                services.append(ports['service']['name'])
                
        try:
            update_table("hosts","host",target,"SERVICES",services)
        except:
            pass

        return services 
    except Exception as error:
        print("ERROR: Could not run service scan")
        print(error)
    



# Attempt anonymous FTP login
def check_ftp(target):
    try:
        ftp = FTP(target)
        ftp.login()
        print("Successful login as anonymous!")
        print("Printing FTP Contents...")
        ftp.dir()
        report_anonftplogin_vuln(target)

    except:
        print("ERROR: Could not login to FTP anonymously")


def report_anonftplogin_vuln(host):
    _type = "Anonymous Login"
    severity = "Due to the low complexity, this is a high-severity vulnerability"
    description = f"Anonymous login was found to work on FTP for \"{host}\"."
    remediation = "Disable anonymous login"

    vals = (None, host, _type, severity, description, remediation)

    insert_to_table("vulns", vals)



# check_ftp("127.0.0.1")
# discover_os("192.168.56.110")

