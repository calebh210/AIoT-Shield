from sql_module import *
from time import sleep
import signal
import netifaces as nif
from simple_term_menu import TerminalMenu


# REFERENCES
#https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
#https://www.geeksforgeeks.org/packet-sniffing-using-scapy/

from scapy.all import *

protocols = set()
potential_credentials = []

def signal_handler(sig, frame):
    print('\n Goodbye!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler) # Check if the users hits ctrl+C

def packet_handler(packet):
      if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors='ignore')

        ### Detect HTTP traffic
        # https://datatracker.ietf.org/doc/html/rfc2616
        if raw_data.startswith("GET") or raw_data.startswith("POST") or raw_data.startswith("PUT") or raw_data.startswith("HEAD"):
            print("HTTP Traffic:", raw_data)
            protocols.add("HTTP")
        ### Detect FTP OR POP3 traffic
        #https://datatracker.ietf.org/doc/html/rfc959
        # https://www.ietf.org/rfc/rfc1939.txt
        # They use the same commands in the header
        if "USER" in raw_data or "PASS" in raw_data or "SYST" in raw_data or "LIST" in raw_data:
            print("Potential POP3 or FTP Traffic:", raw_data)
            print("Analyze the port to determine location:",  packet[TCP].dport)
            protocols.add("FTP or POP3")

            # if "USER" in raw_data or "PASS" in raw_data:
            #     potential_credentials.append(raw_data)
        ### Detect TELNET Traffic
        # https://datatracker.ietf.org/doc/html/rfc854
        elif '\r\n' in raw_data:
            print("Potential Telnet Traffic:", raw_data)
            protocols.add("Telnet")
        ### Detect DNS Traffic
        # This is tricky since DNS is UDP

        #print(protocols)

# Sniff packets
def sniff_packets(nic, host):
    print("Sniffing packets for 30 seconds....")
    if os.getuid() != 0:
        print("ERROR: Root privileges are sniff packets!")
        return 
    sniffer = AsyncSniffer(iface = nic, filter="tcp", prn=packet_handler, store=0)
    sniffer.start()
    sleep(30) ### Make this a variable
    sniffer.stop()
    if len(protocols) != 0:
        report_insecure_protocols(protocols, host)

def report_insecure_protocols(protocols, host):
    # host = "NETWORK"
    _type = "Insecure Protocols and Communication"
    severity = "Due to the low complexity, this is a high-severity vulnerability"
    description = f"Insecure protocols were found to be in use: {protocols}. These use of these protocols on the network allows the potential for cleartext credentials to be sniffed."
    remediation = "Use the secure, encrypted versions of these protocols"

    vals = (None, host, _type, severity, description, remediation)

    insert_to_table("vulns", vals)


# Function to allow the user to select the NIC to sniff on
def select_nic():
    nics = nif.interfaces()
    print("Select the Network Interface you'd like to sniff on \n")
    terminal_menu = TerminalMenu(nics)
    menu_entry_index = terminal_menu.show()
    return nics[menu_entry_index]

#sniff_packets("lo")