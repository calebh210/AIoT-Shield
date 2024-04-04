from sql_module import *
import signal


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
def sniff_packets(nic):
    if os.getuid() != 0:
        print("Root privileges are sniff packets!")
        return
    sniffing = True
    while sniffing: 
        sniff(iface = nic, filter="tcp", prn=packet_handler, store=0)
        

def report_insecure_protocols():
    _type = "Insecure Protocols and Communication"
    severity = "Due to the low complexity, this is a high-severity vulnerability"
    description = f"Insecure protocols were found to be in use: {protocols}. These use of these protocols allows the potential for cleartext credentials to be sniffed."
    remediation = "Use the secure, encrypted versions of these protocols"

    vals = (None, host, _type, severity, description, remediation)

    insert_to_table("vulns", vals)

sniff_packets("lo")