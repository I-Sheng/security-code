#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-493cf1c43792', filter='net 142.250.0.0/16', prn=print_pkt)
