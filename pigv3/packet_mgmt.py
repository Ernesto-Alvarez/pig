import pcapy
import threading
import socket
import datetime
import time
import os

class live_sensor(object):
	#Sensor class
	#This sensor opens a live pcapy capture and sends packets through the output queue
	#The user must define an output function (the put function of a queue is a good choice),
	#a BPF filter and a capture interface.
	
	#Initializer
	def __init__(self,output,interface,pcap_bpf=None):
		self.pcap_handle = pcapy.open_live(interface,65535,True,0)
		self.output = output;

		if pcap_bpf is not None:
			self.pcap_handle.setfilter(pcap_bpf)

		self.sense_thread=threading.Thread(target=self.sense)
		self.sense_thread.daemon=True
		self.sense_thread.start()

	def sense(self):
		#Capture and pass packets as long as the reader is open
		#Tries to get a packet, if there's a socket timeout exception, keep trying!
		#One important issue: socket timeout in ubuntu 14.04LTS (do not remove the try-catch, or the sense thread will crash when idling)
		
		self.end = False

		while not self.end:
			try:
				(h,d) = self.pcap_handle.next()
				if h is None:
					self.end = True
				else:
					self.output(self.extract_info(h,d),True)
			except socket.timeout:
				pass
			except pcapy.PcapError:
				self.end = True
		self.output( { 'type' : 'Capture End'} )

	def extract_info(self,header,packet):
		#The data dumper for the class. Replace this with your own, extracting relevant data from the packet capture.

		return { 'type' : 'Packet capture', 'header' : header, 'packet' : packet, 'packet_id' : os.urandom(16).encode('hex')}

	def kill(self):
		self.end = True
		

class pcap_recorder(object):
	#The PCAP recorder opens a pcap file for writing and takes sensor data via an input function.
	#Compatible data is taken, pcap data is extracted and dumped.

	def __init__(self,input,dump_file):
		null_pcap = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"       
		#For some reason, pcapy dumper objects require having a reader. To avoid requiring superuser privileges, we'll write a null pcap file to the dump file and read that, overwriting it later.
		f = open(dump_file,"w")
		f.write(null_pcap)
		f.close()		

		reader = pcapy.open_offline(dump_file)
		self.dumper = reader.dump_open(dump_file)

		self.input = input

		self.dumper_thread=threading.Thread(target=self.dump)
		self.dumper_thread.daemon=True
		self.dumper_thread.start()

	def dump(self):
		self.end = False
		while not self.end:
			packet = self.input()
			if packet['type'] == 'Capture End':
				self.end = True
			else:
				if packet['type'] == 'Packet capture':
					pcap_header = packet["header"]
					pcap_data = packet["packet"]
					self.dumper.dump(pcap_header,pcap_data)
		self.dumper = None
			
	def kill(self):
		self.end = True
		self.dumper = None
		#self.dumper_thread.join()
		#We need to lose the reference to the dumper to flush and close the pcap file being written

class replay_sensor(object):
	#This sensor opens a pcap file and sends packets through the output queue as if it were live data
	#The user must define an output function (the put function of a queue is a good choice),
	#a BPF filter and a file name
	#Optionally, a replay speed and number of repetitions may be chosen. The replay will be sped up by the replay speed factor and repeated as many times as indicated

	#Currently, BPF appears not to be working

	def __init__(self,output,file,pcap_bpf=None,replay_speed=1,repetitions=1):
		self.output = output;
		self.file = file
		self.repetitions = repetitions
		self.pcap_bpf = pcap_bpf

		#Calculate timing
		pcap_timing_handle = pcapy.open_offline(file)

		if self.pcap_bpf is not None:
			pcap_timing_handle.setfilter(self.pcap_bpf)

		try:
			(h,d) = pcap_timing_handle.next()
		except pcapy.PcapError:
			h = None
			d = None
		if h is None:		#No packets
			self.output( { 'type' : 'Capture End'} )
			return

		self.zero_ts = h.getts()[0] * 1000000 + h.getts()[1]
		self.file_timing = []

		while h is not None:
			ts = ( h.getts()[0] * 1000000 + h.getts()[1] - self.zero_ts ) / replay_speed
			self.file_timing.append(ts)
			try:
				(h,d) = pcap_timing_handle.next()
			except pcapy.PcapError:
				h = None
				d = None

		self.replay_thread=threading.Thread(target=self.replay_all)
		self.replay_thread.daemon=True
		self.replay_thread.start()

	def extract_info(self,header,packet):
		return { 'type' : 'Packet capture', 'header' : header, 'packet' : packet, 'packet_id' : os.urandom(16).encode('hex')}

	def replay_once(self):
		#replay a capture: the capture has at least one packet (the constructor would have aborted otherwise)
		#we send each packet at the time indicated in self.file_timing. The first one goes immediately.
		pcap_handle = pcapy.open_offline(self.file)
		if self.pcap_bpf is not None:
			pcap_timing_handle.setfilter(self.pcap_bpf)

		(h,d) = pcap_handle.next()

		ref = datetime.datetime.now()
		self.output(self.extract_info(h,d),True)

		for i in self.file_timing[1:]:
			(h,d) = pcap_handle.next()			
			now = datetime.datetime.now() - ref
			now_ts = now.microseconds + now.seconds * 1000000 + now.days * 86400000000
			if i > now_ts:
				time.sleep( float(i - now_ts) / 1000000)			
			self.output(self.extract_info(h,d),True)

	def replay_all(self):
		for i in range(self.repetitions):
			self.replay_once()
		self.output( { 'type' : 'Capture End'} )

