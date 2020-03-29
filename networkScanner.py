#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    print("----------------------------------------------")
    print("IP\t\t\t\tMAC address")
    print("----------------------------------------------")
    for element in answered:
        print(element[1].psrc, "\t\t\t", element[1].hwsrc)

scan("10.0.2.1/24")