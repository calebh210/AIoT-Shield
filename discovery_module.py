#!venv/bin/python3
import nmap3
import json
import ipaddress
from sql_module import *

nmap = nmap3.NmapHostDiscovery()

#Find alive hosts. Works with cidr blocks! If a valid host is found, it is added to the DB
def find_alive(target):
    results = nmap.nmap_no_portscan(target)
    try:
        if "/" not in target:
            if (results[target]['state']['state']) == "up":  # This currently doesn't work with hostnames
                print(f"{target} is active")
                add_to_table(target)
            else:
                all_potential_hosts = list(ipaddress.ip_network(target,False).hosts())
                for h in all_potential_hosts:
                    if results[str(h)]['state']['state'] == "up":
                        print(f"{h} is active")
                        add_to_table(str(h))
    except:
        print("ERROR: Could not scan host. Hostname or IP may be invalid")



def add_to_table(entry):
    if not check_if_exists("hosts", "host", entry):
        vals = (entry, None, None, None, None)
        insert_to_table("hosts", vals)
    else:
        print("Host already exists in the database!")