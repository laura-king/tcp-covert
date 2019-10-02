from scapy.all import *
from scapy.layers.inet import IP,TCP

conf.use_pcap = True

l_ip = '129.21.159.83'
lh = '127.0.0.1'
vm_ip = '172.16.74.133'
k_ip = '129.21.158.188'

# first ask source and destination addrs 
#out_ip.src = input("Source: ")
#out_ip.src = lh

#out_ip.dst = input("Destination: ")
#out_ip.dst = lh


##### ENCODING 
# ask usr for message to encode 
msg = input("Message to send: ")
# loop to encode message - multiply each char by 256
for letter in msg:
	encoded_letter = ord(letter) * 256
	out_ip = IP(dst=k_ip)/TCP(sport=encoded_letter, dport=8888)
	#out_ip.id = encoded_letter
	# send packet! 
	send(out_ip)

##### DECODING
'''
for inc_packet in sniff(iface=""):
	# if this packet is for me 
	if inc_packet.src == out_ip.dst:
		# check ID field and decode 
		encoded_letter_out = inc_packet.id
		decoded_letter = chr( encoded_letter_out / 256 )
'''


		
