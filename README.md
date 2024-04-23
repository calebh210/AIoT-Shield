# AIoT Shield

```
           ______    _________   ________    _      _     _
     /\   |_   _/ __ \__   __|  / ____| |   (_)    | |   | |         |`-._/\_.-`|
    /  \    | || |  | | | |    | (___ | |__  _  ___| | __| |         |    ||    |                
   / /\ \   | || |  | | | |     \___ \| '_ \| |/ _ \ |/ _` |         |___o()o___|
  / ____ \ _| || |__| | | |     ____) | | | | |  __/ | (_| |         |__((<>))__|
 /_/    \_\_____\____/  |_|    |_____/|_| |_|_|\___|_|\__,_|         \   o\/o   /
                                                                      \   ||   /
                                                                       \  ||  /
                                                                        '.||.'

```
AIoT Shield is a vulnerability scanner intended to enumerate IoT devices for potential vulnerabilities. AIoT Shield makes use of the GPT-4 LLM to perform security checks.

## Requirements:
- Python3
- pip3
- OpenAI API Key

## Installation:
```
  git clone https://github.com/calebh210/AIoT-Shield.git
  cd AIoT-Shield
  python3 -m venv .venv
  source .venv/bin/activate
  pip3 -r requirements.txt
```

Alternatively, use the installation script

```
./install.sh
```

## Usage

Launch the program
```
sudo ./main.py
```
```
List of commands to run:

    scan [ip] - Run a host discovery check
    port_scan [ip] - Scan an IP or CIDR block for open ports
    os_scan [ip] - (Requires Root) - Detect the OS and version of a host
    cve_scan [ip] - Scan a host for services and potential CVEs associated with them.
    all_scan - Perform all scans
    

    Enter Target Mode:
    select_target 

    Commands In Target Mode:
    brute_force - Perform a brute force / default credential password spray on a login portal
    sniff_network - Sniff a network for unencrypted traffic
    generate_report - 

    show_table - View the data saved in the enumeration table
    clear_table - Clear the enumeration table

    /! [arg] - Run Shell Commands
```

