#!venv/bin/python3
import nmap3
import signal
import sys
from discovery_module import find_alive 
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

colorama_init()


def signal_handler(sig, frame):
    print('\n Goodbye!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler) # Check if the users hits ctrl+C

#nmap = nmap3.Nmap()
#results = nmap.nmap_os_detection("192.168.56.110")
#print(results)


def mainMenu():
    isBreak = False
    while not isBreak:
        target = input(shell)
        if target == "":
            print("Type \"help\" for a list of valid commands")
        if target == "exit":
            isBreak = True
        if target == "help":
            helpMenu()
        #find_alive(target)

shell = f"{Fore.CYAN}IoT Buster # {Style.RESET_ALL}"


def helpMenu():
    print("test")


mainMenu()