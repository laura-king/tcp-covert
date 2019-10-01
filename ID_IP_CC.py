from scapy.all import IP

out_ip = IP()

# first ask source and destination addrs 
out_ip.src = input("Source: ")
out_ip.dst = input("Destination: ")

##### ENCODING 
# ask usr for message to encode 
msg = input("Message to send: ")
# loop to encode message - multiply each char by 256
for letter in msg:
	encoded_letter = ord(letter) * 256
	out_ip.id = encoded_letter
	# send packet! 
	send(out_ip)

##### DECODING
for inc_packet in sniff(iface=""):
	# if this packet is for me 
	if inc_packet.src == out_ip.dst:
		# check ID field and decode 
		encoded_letter_out = inc_packet.id
		decoded_letter = char( encoded_letter_out / 256 )


		
