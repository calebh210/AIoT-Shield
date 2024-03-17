#!venv/bin/python3
import signal
import sys
import psutil
from discovery_module import find_alive 
from enumeration_module import *
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from sql_module import *

colorama_init()

#TODO Look into making this a state machine: https://auth0.com/blog/state-pattern-in-python/

def signal_handler(sig, frame):
    print('\n Goodbye!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler) # Check if the users hits ctrl+C

#nmap = nmap3.Nmap()
#results = nmap.nmap_os_detection("192.168.56.110")
#print(results)

#Main menu page
def mainMenu():
    helpMenu()
    #Testing out NIC stuff
    #print("NIC info:")
    #print(psutil.net_if_addrs())
    isBreak = False
    shell = Shell()
    while not isBreak:
        target, arg = "", ""
        inputs = input(shell)
        split_inputs = inputs.split()
        if len(split_inputs) == 1:
             target = split_inputs[0]
        elif len(split_inputs) == 2:
            target, arg = split_inputs

        if target == "":
            print("Type \"help\" for a list of valid commands")
        elif target == "exit":
            isBreak = True
        elif target == "help":
            helpMenu()
        elif target == "scan":
            find_alive(arg)
            shell.update_module("<scanner> ")
        elif target == "clear_table":
            clear_table("hosts")
        elif target == "show_hosts":
            alive_hosts = read_table("hosts")
            display_table(alive_hosts)
            #print(alive_hosts)
        elif target == "port_scan":
            scan_ports(arg)
        elif target == "os_scan":
            discover_os(arg)
        elif target == "cve_scan":
            scan_cves(arg)
        elif target == "all_scan":
            discover_os(arg)
        elif target == "/!":
            os.system(arg)
        else:
            print(f"\"{target}\" is not a valid command. Type \"help\" for a list of valid commands")



class Shell:

    def __init__  (self, module=""):  
        #The default shell header
        self._module = f"{module}"

    def __str__(self):
        return f"{Fore.CYAN}IoT Buster {Fore.WHITE}{self._module}{Fore.CYAN}# {Style.RESET_ALL}"

    def update_module(self, new_module):
        self._module = new_module
    


def helpMenu():
    #Ascii art from https://patorjk.com/software/taag
    print(
    """ 
                          ,----,                                                                          
                        ,/   .`|                                                                          
   ,---,              ,`   .'  :            ,---,.                             ___                        
,`--.' |            ;    ;     /          ,'  .'  \                          ,--.'|_                      
|   :  :   ,---.  .'___,/    ,'         ,---.' .' |         ,--,             |  | :,'             __  ,-. 
:   |  '  '   ,'\ |    :     |          |   |  |: |       ,'_ /|   .--.--.   :  : ' :           ,' ,'/ /| 
|   :  | /   /   |;    |.';  ;          :   :  :  /  .--. |  | :  /  /    '.;__,'  /     ,---.  '  | |' | 
'   '  ;.   ; ,. :`----'  |  |          :   |    ; ,'_ /| :  . | |  :  /`./|  |   |     /     \ |  |   ,' 
|   |  |'   | |: :    '   :  ;          |   :     \|  ' | |  . . |  :  ;_  :__,'| :    /    /  |'  :  /   
'   :  ;'   | .; :    |   |  '          |   |   . ||  | ' |  | |  \  \    `. '  : |__ .    ' / ||  | '    
|   |  '|   :    |    '   :  |          '   :  '; |:  | : ;  ; |   `----.   \|  | '.'|'   ;   /|;  : |    
'   :  | \   \  /     ;   |.'           |   |  | ; '  :  `--'   \ /  /`--'  /;  :    ;'   |  / ||  , ;    
;   |.'   `----'      '---'             |   :   /  :  ,      .-./'--'.     / |  ,   / |   :    | ---'     
'---'                                   |   | ,'    `--`----'      `--'---'   ---`-'   \   \  /           
                                        `----'                                          `----'        
    
    """)

    print("""
    List of commands to run:
    scan [ip]
    port_scan [ip]
    os_scan [ip] - Requires root
    cve_scan [ip] - not currently working
    all_scan - Requires root
    

    show_hosts
    clear_table
    /! [arg] - Run Shell Commands

    # Info - Load information on the current module

    *** DISCLAIMER! Only use this tool on networks where you have explicit permission! ***
    """)

#Disply hosts which were discovered to be alive
def display_table(data):
    print(
f"""┌────────────┐
│    Host    │      
└────────────┘""")

    for item in data:
        print(
f"""
┌────────────┐
│ {item[0]} │           {item[1]}       {item[2]}
└────────────┘
""")


mainMenu()