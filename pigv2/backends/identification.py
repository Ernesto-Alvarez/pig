import threading
import ipaddr

class generic_identifier(object):
	def __init__(self,input,output):

		#Addresses not to be collected
		self.banned = [ipaddr.IPv4Address('0.0.0.0')]

		#Input and output functions (usually q1.get an q2.put)
		self.input = input;
		self.output = output;

		self.x=threading.Thread(target=self.process)
		self.x.daemon=True
		self.x.start()

	def process(self):
		#The processing thread. Take data from the input(s) and generate information to be sent to the output.
		#This generic backend takes one packet from the input and is the base for the station detector. Other more complex backend may be more effective if not inherited from this.
		
		while True:
			data = self.input()
			information = self.extract_info(data)
			if information['IP'] not in self.banned:
				self.output(information)

	def extract_info(self,data):
		raise(NotImplementedError)

class ip_identifier(generic_identifier):
	def extract_info(self,data):
		identification = {}
		identification['station_id'] = data['station_id']
		identification['IP'] = data['source']
		identification['type'] = 'IP Identification'
		identification['reference_distance'] = 1

		return identification