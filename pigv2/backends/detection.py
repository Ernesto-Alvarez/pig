import threading

class generic_backend(object):
	def __init__(self,input,output):

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
			self.output(information)

	def extract_info(self,data):
		raise(NotImplementedError)

class source_detector(generic_backend):
	def extract_info(self,data):
		source = {}
		source['station_id'] = data['station_id']
		source['timestamp'] = data['timestamp']
		source['type'] = 'Station detection'
		source['reference_distance'] = 1

		return source