import socket
import os
import struct
import threading
import time
import sys

from netaddr import IPNetwork,IPAddress
from ctypes import *

class Scan():

	# Host to listen on
	host   = socket.gethostbyname(socket.gethostname())

	# Subnet to target
	subnet = "192.168.0.0/24"

	# Message we'll check ICMP responses for
	magic_message = "ANTISEC!"

	def udp_sender(subnet,magic_message):
		sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
		for ip in IPNetwork(subnet):
			try:
				sender.sendto(magic_message,("%s" % ip,65212))
			except:
				pass
        
                
	class IP(Structure):
    
		_fields_ = [
			("ihl",           c_ubyte, 4),
			("version",       c_ubyte, 4),
			("tos",           c_ubyte),
			("len",           c_ushort),
			("id",            c_ushort),
			("offset",        c_ushort),
			("ttl",           c_ubyte),
			("protocol_num",  c_ubyte),
			("sum",           c_ushort),
			("src",           c_ulong),
			("dst",           c_ulong)
		]
    
		def __new__(self, socket_buffer=None):
			return self.from_buffer_copy(socket_buffer)    
        
		def __init__(self, socket_buffer=None):

			# Map constants to their names
			self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        
			# Readable IP addresses
			self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
			self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
    
			# Human readable protocol
			try:
				self.protocol = self.protocol_map[self.protocol_num]
			except:
				self.protocol = str(self.protocol_num)
            


	class ICMP(Structure):
    
		_fields_ = [
			("type",         c_ubyte),
			("code",         c_ubyte),
			("checksum",     c_ushort),
			("unused",       c_ushort),
			("next_hop_mtu", c_ushort)
			]
    
		def __new__(self, socket_buffer):
			return self.from_buffer_copy(socket_buffer)    

		def __init__(self, socket_buffer):
			pass

	if os.name == "nt":
		socket_protocol = socket.IPPROTO_IP 
	else:
		socket_protocol = socket.IPPROTO_ICMP
    	
    	try:
		sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
		sniffer.bind((host, 0))
	except socket.error:
		print "\n[!]PyCat requires administrative privilege to scan the local network. Exiting."
		sys.exit(0)

	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# If we're on Windows we need to send some ioctls
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


	# Start sending packets 
	t = threading.Thread(target=udp_sender,args=(subnet,magic_message))
	t.start()        

	# Timer, so that we won't get stuck in case we cannot send CTRL+C 
	try:
		start = time.time()
		while (time.time() - start < 15):
        
			# Read in a packet
			raw_buffer = sniffer.recvfrom(65565)[0]
        
			# Create an IP header from the first 20 bytes of the buffer
			ip_header = IP(raw_buffer[0:20])
    
			# If it's ICMP we want it
			if ip_header.protocol == "ICMP":
            
				# Calculate where our ICMP packet starts
				offset = ip_header.ihl * 4
				buf = raw_buffer[offset:offset + sizeof(ICMP)]
            
				# ICMP structure
				icmp_header = ICMP(buf)
            
				# Check for the TYPE 3 and CODE 3          
				if icmp_header.code == 3 and icmp_header.type == 3:
					# Make sure we recieve response
					if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    
						# Test for our magic message
						if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
							print "[+]Host Up: %s" % ip_header.src_address
							
	# Handle CTRL+C
	except KeyboardInterrupt:
		# If  Windows, turn off promiscuous mode
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)	
