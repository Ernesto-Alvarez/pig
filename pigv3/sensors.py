import pcapy
import threading
import socket
import datetime
import time

class live_sensor(object):
	#Sensor class
	#This sensor opens a live pcapy capture and sends packets through the output queue
	#The user must define an output function (the put function of a queue is a good choice),
	#a BPF filter and a capture interface.
	
	#This class may be superseded if a multi-registration filter is implemented

	#Initializer
	#Warning! Output is an output function with one parameter. A good candidate is the put function of a queue.
	def __init__(self,output,interface,pcap_bpf=None):
		self.pcap_handle = pcapy.open_live(interface,65535,True,0)
		self.output = output;

		if pcap_bpf is not None:
			self.pcap_handle.setfilter(pcap_bpf)

		self.x=threading.Thread(target=self.sense)
		self.x.daemon=True
		self.x.start()

	def sense(self):
		#The capture thread. You should not need to change this in subclasses
		#Tries to get a packet, if there's a socket timeout exception, keep trying!
		#One important issue: pcap timeout in ubuntu 14.04LTS (do not remove the try-catch, or the sense thread will crash when idling)
		
		while True:
			try:
				(h,d) = self.pcap_handle.next()
				self.output(self.extract_info(h,d),True)
			except socket.timeout:
				pass

	def extract_info(self,header,packet):
		#The data dumper for the class. Replace this with your own, extracting relevant data from the packet capture.

		return { 'type' : 'PCAP Packet', 'header' : header, 'packet' : packet }

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

		self.x=threading.Thread(target=self.dump)
		self.x.daemon=True
		self.x.start()

	def dump(self):
		while True:
			packet = self.input()
			pcap_header = packet["header"]
			pcap_data = packet["packet"]
			self.dumper.dump(pcap_header,pcap_data)

class replay_sensor(object):
	#This sensor opens a pcap file and sends packets through the output queue as if it were live data
	#The user must define an output function (the put function of a queue is a good choice),
	#a BPF filter and a file name

	#Currently, BPF appears not to be working

	def __init__(self,output,file,pcap_bpf=None,timing_multiplier=1):

		#Calculate timing
		self.file_timing = []
		pcap_timing_handle = pcapy.open_offline(file)
		if pcap_bpf is not None:
			pcap_timing_handle.setfilter(pcap_bpf)

		(h,d) = pcap_timing_handle.next()
		#Empty files will return None. Let it crash for now.
		self.zero_ts = h.getts()[0] * 1000000 + h.getts()[1]

		while h is not None:
			ts = ( h.getts()[0] * 1000000 + h.getts()[1] - self.zero_ts ) / timing_multiplier
			self.file_timing.append(ts)
			(h,d) = pcap_timing_handle.next()

		self.pcap_handle = pcapy.open_offline(file)
		self.output = output;

		if pcap_bpf is not None:
			self.pcap_handle.setfilter(pcap_bpf)

		self.x=threading.Thread(target=self.replay)
		self.x.daemon=True
		self.x.start()

	def replay(self):
		print self.file_timing
		ref = datetime.datetime.now()
		(h,d) = self.pcap_handle.next()
		self.output({ 'type' : 'PCAP Packet', 'header' : h, 'packet' : d },True)
		print "PCAP Time: 0"

		for i in self.file_timing[1:]:
			now = datetime.datetime.now() - ref
			now_ts = now.microseconds + now.seconds * 1000000 + now.days * 86400000000
			print "Real Time: " + str(now_ts)

			if i > now_ts:
				#print "sleep " + str((i - now_ts))
				time.sleep( float(i - now_ts) / 1000000)
			print "PCAP Time: " + str(i)
		now = datetime.datetime.now() - ref
		now_ts = now.microseconds + now.seconds * 1000000 + now.days * 86400000000
		print "Real Time: " + str(now_ts)
