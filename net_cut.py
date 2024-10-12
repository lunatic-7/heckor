#!/usr/bin/env python
import netfilterqueue


def process_packet(packet):
    print(packet)
    packet.drop()  # It will cut the internet connection of the target, as we are dropping the packets
    # packet.accept() # To let the packet move forward to its destination


queue = netfilterqueue.NetfilterQueue()  # Creating an instance of NetfilterQueue() class
queue.bind(0, process_packet)  # 0 is the queue number of the queue we have created using this command in terminal:
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# And process_packet is a callback function which will be executed on all the packets +nt in the queue
queue.run()
