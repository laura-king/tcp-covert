#! /usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP,TCP

out_ip = IP()
# end of message flag
eom = ord("!") * 256

# first ask source and destination addrs 
#out_ip.src = input("Source: ")
#out_ip.dst = input("Destination: ")

#loopback
out_ip.src = "127.0.0.1"
out_ip.dst ="127.0.0.1"

##### ENCODING 
# ask usr for message to encode 
msg = input("Message to send: ")
# loop to encode message - multiply each char by 256
for letter in msg:
	encoded_letter = ord(letter) * 256
	out_ip.id = encoded_letter
	# send packet! 
	send(out_ip)

# finally send eom 
out_ip.id = eom
send(out_ip)