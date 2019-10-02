#! /usr/bin/env python3
from scapy.all import IP

eom = "!" 
enc_let = ""
global msg
msg = "" 

def sniff_packet(intface):
	sniff(iface=intface, prn=process_packet, store=False, count=6)

def process_packet(packet):
	global msg
	if packet.src == '127.0.0.1':
		return
	enc_let = int(packet.id)
	dec_let = chr(enc_let // 256)
	if not msg:	
		msg += dec_let
	elif dec_let != msg[-1]:
		msg += dec_let

sniff_packet("lo")
print(msg)


