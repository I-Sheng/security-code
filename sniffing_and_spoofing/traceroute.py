#!/usr/bin/env python3
from scapy.all import *

def traceroute():
    for i in range(2,50):
        a = IP()
        a.dst = '128.119.245.12'
        a.ttl = i
        b = ICMP()
        send(a/b)



traceroute()


