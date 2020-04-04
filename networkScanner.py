#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-t", "--target", dest="ip", help="Provide IP Range")
    (options, arguments) = parser.parse_args()

    if not options.ip:
        parser.error("Please specify the IP. use --help for more info")
    return options


def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    clients = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "MAC": element[1].hwsrc}
        clients.append(client_dict)

    return clients

def print_results(results):
    print("IP Address\t\t\tMAC Address")
    print("---------------------------------------------------------")
    for result in results:
        print(result["ip"], "\t\t\t", result["MAC"])

options = get_arguments()

print_results(scan(options.ip))
