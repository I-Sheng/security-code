#!/usr/bin/env python3
from scapy.all import *

def spoof(src):
    a = IP()
    a.src = src
    a.dst = '10.9.0.6'
    b = ICMP()
    p = a/b
    send(p)


spoof('10.0.2.3')
