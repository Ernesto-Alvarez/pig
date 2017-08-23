import threading
import ipaddr
import time

#Hub: takes one message from the input queue and replicates it across all output queues
class hub(object):
	def __init__(self,input,output):
		#Input and output functions (usually q1.get and [q2.put,q3.put....])
		self.input = input;
		self.output = output;

		self.x=threading.Thread(target=self.process)
		self.x.daemon=True
		self.x.start()

	def process(self):
		while True:
			data = self.input()
			for i in self.output:
				i(data)

#Network range gate: takes an IP packet from the input queue and passes it to the output queue if and only if the IP source is within a list of dymanically changing networks.
#Takes an input function, an output function and an update function (which returns a list of addresses, usually database.ip_network_table.ip_list)
class network_range_gate(object):
	def __init__(self,input,output,update,update_frequency=0.5):
		self.input = input;
		self.output = output;
		self.addresses = []
		self.db_semaphore = threading.Semaphore()
		self.passed = []

		self.update_function = update
		self.update_frequency = update_frequency

		self.x=threading.Thread(target=self.process)
		self.x.daemon=True
		self.x.start()

		self.y=threading.Thread(target=self.update_addresses)
		self.y.daemon=True
		self.y.start()

#	def debug_data(self):
#		print "Gating list", self.addresses
#		print "Recently passed", self.passed
#		self.passed = []


	def process(self):
		while True:
			data = self.input()
			self.db_semaphore.acquire()
			try:
				for i in self.addresses:
					if i.Contains(data['source']):
						self.output(data)
						#self.passed.append(data['source'])
						break
			except:
				pass
			self.db_semaphore.release()

	def update_addresses(self):
		while True:
			time.sleep(self.update_frequency) # to avoid a busy loop
			self.db_semaphore.acquire()
			self.addresses = self.update_function()
			self.db_semaphore.release()
			
		
