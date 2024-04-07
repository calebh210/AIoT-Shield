#!venv/bin/python3
import signal
import sys
import psutil
from discovery_module import find_alive 
from enumeration_module import *
from bruting_module import bruting_attack
from ai_module import set_api_key, generate_report
from sniffing_module import *
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from sql_module import *
from simple_term_menu import TerminalMenu

colorama_init()

#TODO Look into making this a state machine: https://auth0.com/blog/state-pattern-in-python/
#See also: https://python-3-patterns-idioms-test.readthedocs.io/en/latest/StateMachine.html



def signal_handler(sig, frame):
    print('\n Goodbye!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler) # Check if the users hits ctrl+C

#nmap = nmap3.Nmap()
#results = nmap.nmap_os_detection("192.168.56.110")
#print(results)

#Main menu page

class DefaultState:

    def __init__(self):
        self.shell = Shell()

    def init_shell(self):
        inputs = input(self.shell)
        return inputs

    def update_shell(self, data):
        self.shell.update_module(data)

class StateMachine:
    def __init__(self):
        self.current_state = None

    def change_state(self, new_state):
        if self.current_state:
            self.current_state.exit()
        self.current_state = new_state
        self.current_state.enter()

class MenuState(DefaultState):

    def __init__(self, machine):
        self.state_machine = machine
        super().__init__()

    def enter(self):
        self.mainMenu()

    def exit(self):
        pass

    def mainMenu(self):
        helpMenu()
        #Testing out NIC stuff
        #print("NIC info:")
        #print(psutil.net_if_addrs())
        isBreak = False
        while not isBreak:
            inputs = super().init_shell()
            target, arg = "", ""
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
                 
            elif target == "clear_table":
                clear_table("hosts")
            elif target == "show_hosts":
                alive_hosts = read_table("hosts")
                display_table(alive_hosts)
                #print(alive_hosts)
            elif target == "select_target":
                alive_hosts = read_table("hosts")
                if (alive_hosts == []):
                    print("No targets to select from!")
                else:    
                    selected = select_target(alive_hosts)
                    super().update_shell(selected)
                    targ_menu = TargetMenu(selected)
                    self.state_machine.change_state(targ_menu)

            elif target == "port_scan":
                scan_ports(arg)
            elif target == "os_scan":
                discover_os(arg)
            elif target == "cve_scan":
                scan_cves(arg)
            elif target == "all_scan":
                discover_os(arg)
            elif target == "set_api_key":
                set_api_key(False) 
            elif target == "/!":
                os.system(arg)
            else:
                print(f"\"{target}\" is not a valid command. Type \"help\" for a list of valid commands")

class TargetMenu(DefaultState):

    def __init__(self, target):
        self.target = target
        super().__init__()
        super().update_shell(target)

    def enter(self):
        print("Entering Target Menu")
        print(f"Attacking {self.target}")
        self.target_menu()

    def exit(self):
        print("Exiting Target Menu")

    def target_help_menu(self):
        print("""
        
            COMMANDS - 

            sniff_network - Sniff the network of the current target for insecure communication

            brute_force - Attempts to login using default credentials

            generate_report - Generates a report of all found vulnerabilities

        """)
    
    def target_menu(self):
        isBreak = False
        while not isBreak:
            inputs = super().init_shell()
            target, arg = "", ""
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
                self.target_help_menu()
            elif target == "brute_force":
                bruting_attack(self.target)
            elif target == "generate_report":
                data = read_table_by_key("vulns","host",self.target)
                data2 = read_table_by_key("hosts","host",self.target)
                report = generate_report(data, data2)
                if arg != "":
                    f = open(arg, "w")
                    f.write(report)
                    f.close()
                    print(f"Report saved to {arg}!")
                else:
                    print(report)
            elif target == "sniff_network":
                sniff_packets(select_nic(), self.target)


class Shell:

    def __init__  (self, module=""):  
        #The default shell header
        self._module = f"{module}"

    def __str__(self):
        return f"{Fore.CYAN}IoT Buster {Fore.WHITE} {self._module}{Fore.CYAN}# {Style.RESET_ALL}"

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
    
    In Target Mode:
    brute_force

    show_hosts
    clear_table
    select_target
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

def select_target(data):
    options = []
    for item in data:
        options.append(str(item[0]))
    terminal_menu = TerminalMenu(options)
    menu_entry_index = terminal_menu.show()
    return options[menu_entry_index]


def main():
    
    setup_table() # Sets up the table if it doesnt already exists
    state_machine = StateMachine() # Init state machine
    main_menu_state = MenuState(state_machine) #Sets up main menu state
    state_machine.change_state(main_menu_state) #Puts state machine into main menu state



if __name__ == '__main__':
    main()

