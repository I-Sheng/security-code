#!/usr/bin/env python3
from scapy.all import *


def spoof(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = pkt[IP]
        icmp = pkt[ICMP]

        # Build spoofed echo reply
        reply = IP(src=ip.dst, dst=ip.src) /\
        ICMP(type=0, id=icmp.id, seq=icmp.seq)/\
        icmp.payload

        send(reply, verbose=0)
        print(f"[+] Spoofed reply: {reply[IP].src} -> {reply[IP].dst}")


def main():
    sniff(filter='icmp and icmp[icmptype] = icmp-echo', prn=spoof, store=0)


if __name__ == "__main__":
    main()
