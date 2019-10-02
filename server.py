#! /usr/bin/env python3
from scapy.all import IP

eom = "!" 
enc_let = ""
msg = "" 

def sniff_packet(intface):
	sniff(iface=intface, prn=process_packet, store=False)

def process_packet(packet):
	enc_let = int(packet.id)
	dec_let = chr(enc_let // 256)
	msg += dec_let

sniff_packet("lo")
print(msg)


