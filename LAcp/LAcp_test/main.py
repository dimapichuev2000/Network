import scapy.all as scapy
from scapy.contrib.lacp import SlowProtocol, LACP
from scapy.layers.inet import Ether, Dot3
from scapy.all import *


from scapy.all import *
import time

__version__ = "0.0.1"

def handle_arp_packet(packet):

    # Match ARP requests
    if packet[scapy.ARP].op == scapy.ARP.who_has:
        print('New ARP Request')
        print(packet.summary())
        print(ls(packet))
        print(packet[Ether].src, "has IP", packet[scapy.ARP].psrc)

    # Match ARP replies
    if packet[scapy.ARP].op == scapy.ARP.is_at:
        print('New ARP Reply')
        print(packet.summary())
        #print(ls(packet))

    return

if __name__ == "__main__":
    pkts = sniff(count=5, filter="arp")
    pkts.summary()