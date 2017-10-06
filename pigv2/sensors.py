import datetime
import impacket
from impacket import ImpactDecoder
from impacket import nmb
import ipaddr
import pcapy
import Queue
import socket
import threading

from pigv2.auxiliary.addressing import mac_address

class ethernet_sensor(object):
	#Sensor class
	#This is an not-quite-abstract class for handling packet arrivals. Most of the routine tasks are defined in this abstract class.
	#Final user is to define a BPF filter (optional), a sanity check function (optional) and an information extraction function (mandatory). 
	#Failure to define a BPF will likely require a sanity check, unless you are detecting on the Ethernet layer (and I wouldn't count on that anyway).
	#This class might work, but it should be mainly used as base class for more complex filters.


	#BPF filter: use this to filter the packets sent to you, preferred compared to sanity checks as it saves interrupts.
	#Network parameters may not be defined, so you should not refer to netmasks and network data.
	pcap_bpf = None

	#Initializer
	#Warning! Output is an output function with one parameter. A good candidate is the put function of a queue.
	def __init__(self,output,interface):
		self.pcap_handle = pcapy.open_live(interface,1000,True,0)

		#The data is dumped in a queue of pairs of addresses
		self.output = output;

		if self.pcap_bpf:
			self.pcap_handle.setfilter(self.pcap_bpf)

		self.x=threading.Thread(target=self.sense)
		self.x.daemon=True
		self.x.start()
		self.decoder=impacket.ImpactDecoder.EthDecoder()

	def sense(self):
		#The capture thread. You should not need to change this in subclasses
		#Tries to get a packet, if there's a socket timeout exception, keep trying!
		#One important issue: pcap timeout in ubuntu 14.04LTS (do not remove the try-catch, or the sense thread will crash when idling)
		
		while True:
			try:
				(h,d) = self.pcap_handle.next()
				if (self.sanity_check(d)):
					self.output(self.extract_info(d),True)
				else:
					print "sanity check failed"
			except socket.timeout:
				pass


	def sanity_check(self,packet):
		#Sanity checks go here.
		#Return false if the packet data appears not to be sane.
		#Return true if the packet data is consistent

		#True for now, maybe we should check for ethernet CRC-32? Beware hardware assisted error checking!

		return True

	def extract_info(self,packet):
		#The data dumper for the class. Replace this with your own, extracting relevant data from the packet capture.

		analysis = self.decoder.decode(packet)

		return { 'source' : mac_address(analysis.get_ether_shost().tolist()), 'destination' : mac_address(analysis.get_ether_dhost().tolist()), 'station_id' : mac_address(analysis.get_ether_shost().tolist()),  'reporter' : [0], 'protocol' : [0], 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : analysis }

class l3_protocol_sensor(ethernet_sensor):


	def extract_info(self,packet):
		#The data dumper for the class. Replace this with your own, extracting relevant data from the packet capture.

		analysis = self.decoder.decode(packet)

		if analysis.get_ether_type() < 1536:		#Not an ethertype. LLC travels within frame
			llc = analysis.child()
			ethertype = llc.get_DSAP()
		else:
			ethertype = analysis.get_ether_type()

		if ethertype == 170:				#Still not a DSAP/Ethertype/PID, but a SNAP packet
			snap = llc.child()
			ethertype = snap.get_protoID()

		return { 'protocol' : ethertype, 'station_id' : mac_address(analysis.get_ether_shost().tolist()), 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : analysis }




class arp_sensor(ethernet_sensor):
	pcap_bpf = 'arp'

	def ip_list2int(self,iplist):
		powers = [16777216,65536,256,1]
		return reduce(lambda x,y: x+y, [a*b for a,b in zip(iplist,powers)])

	def sanity_check(self,packet):

		#Ethernet sanity checks
		#Does it have the correct length?
		if (len(packet) < 14):
			return False

		eth = self.decoder.decode(packet)

		if (eth.get_ether_type() != 2054):		#Not ARP -> not interested
			return False

		arp = eth.child()

		if (arp.get_ar_sha() != eth.get_ether_shost().tolist()):	#spoofer
			return False

		return True

	def extract_info(self,packet):
		eth = self.decoder.decode(packet)
		arp = eth.child()

		return { 'source' : ipaddr.IPv4Address(self.ip_list2int(arp.get_ar_spa())), 'destination' : ipaddr.IPv4Address(self.ip_list2int(arp.get_ar_tpa())), 'station_id' : mac_address(eth.get_ether_shost().tolist()),  'reporter' : [0,0x806], 'protocol' : [0,0x800], 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : eth }

#Generic IP sensor. If used, it should be gated to prevent detection of foreign hosts as locals.
class ip_sensor(ethernet_sensor):
	pcap_bpf = 'ip'

	def extract_info(self,packet):
		eth_packet = self.decoder.decode(packet)
		ip_packet = self.decoder.decode(packet).child()

		return { 'source' : ipaddr.IPv4Address(ip_packet.get_ip_src()), 'destination' : ipaddr.IPv4Address(ip_packet.get_ip_dst()), 'station_id' : mac_address(eth_packet.get_ether_shost().tolist()),  'reporter' : [0,0x800], 'protocol' : [0,0x800], 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : eth_packet }

	def sanity_check(self,packet):

		#Ethernet sanity checks
		#Does it have the correct length?
		if (len(packet) < 14):
			return False

		eth = self.decoder.decode(packet)

		if (eth.get_ether_type() != 2048):		
			return False

		return True




		

class ip_local_bcast_sensor(ip_sensor):
	pcap_bpf = 'ip dst 255.255.255.255'

class ip_local_multicast_sensor(ip_sensor):
	pcap_bpf = 'ip dst 239.255.255.250 or ip dst 239.255.255.253 or ip dst net 224.0.0.0/24'

class ip_directed_bcast_sensor(ip_sensor):
	pcap_bpf = 'ether dst host ff:ff:ff:ff:ff:ff and ip and not (ip dst net 224.0.0.0/3)'

	def sanity_check(self,packet):

		eth = self.decoder.decode(packet)
		ip = eth.child()

		source = ipaddr.IPv4Address(ip.get_ip_src())
		destination = ipaddr.IPv4Address(ip.get_ip_dst())

		#Here we need to check whether the source is within the network address of the destination, to rule out a directed broadcast coming from the outside.
		#We shall assume for now that directed broadcasts like that do not happen		

		return True

class nbns_sensor(ip_sensor):
	pcap_bpf = 'udp dst port 137'

	def extract_info(self,packet):

		eth_packet = self.decoder.decode(packet)
		ip_packet = self.decoder.decode(packet).child()
		udp_packet = ip_packet.child()
		nbns_packet = nmb.NetBIOSPacket(udp_packet.child().get_packet())

		nbns_name = nmb.decode_name(nbns_packet.get_answers())[1][0:15]
		nbns_type = ord(nmb.decode_name(nbns_packet.get_answers())[1][15])

		return { 'source' : [nbns_name,nbns_type], 'destination' : None, 'station_id' : mac_address(eth_packet.get_ether_shost().tolist()),  'reporter' : [0,0x800,17,137], 'protocol' : [0,0x800,17,137], 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : eth_packet }


class ipv6_mcast_sensor(ethernet_sensor):
	pcap_bpf = 'ip6 multicast'
	def sanity_check(self,packet):
		#Sanity checks go here.
		#Return false if the packet data appears not to be sane.
		#Return true if the packet data is consistent

		#True for now, maybe we should check for ethernet CRC-32? Beware hardware assisted error checking!

		return True

	def extract_info(self,packet):
		#The data dumper for the class. Replace this with your own, extracting relevant data from the packet capture.

		analysis = self.decoder.decode(packet)

		return { 'source' : mac_address(analysis.get_ether_shost().tolist()), 'destination' : mac_address(analysis.get_ether_dhost().tolist()), 'station_id' : mac_address(analysis.get_ether_shost().tolist()),  'reporter' : [0], 'protocol' : [0], 'timestamp' : datetime.datetime.utcnow(), 'rawdata' : packet, 'decode' : analysis }
	
