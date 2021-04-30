#!/usr/bin/env python3
import scapy.all as scapy
import optparse
def get_arg():
    parse=optparse.OptionParser()
    parse.add_option("-t","--target", dest="target", help="Takes the target IP")
    return parse.parse_args()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=0)[0]
    clients_list=[]
    for element in answered_list:
        client_dict={"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\tMAC Address", end="\n_________________________________________________\n")
    for element in result_list:
        print(element["ip"]+"\t"+element["mac"])
options = get_arg()[0]
client_list = scan(options.target)
print_result(client_list)