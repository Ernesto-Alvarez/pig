import threading
import copy
import random

class generic_table(object):
	def __init__(self,input):
		self.db = {}
		self.input = input
		self.db_semaphore = threading.Semaphore()
	
		self.x=threading.Thread(target=self.collect)
		self.x.daemon=True
		self.x.start()

	def collect(self):
		raise(NotImplementedError)

	def dump(self):
		self.db_semaphore.acquire()
		retval = copy.copy(self.db)
		self.db_semaphore.release()
		return retval

class station_detection_table(generic_table):
	def collect(self):
		while True:
			report = self.input()

			station_id = report['station_id']
			timestamp = report['timestamp']

			self.db_semaphore.acquire()
			self.db[station_id] = timestamp
			self.db_semaphore.release()

class ip_identification_table(generic_table):
	def collect(self):
		while True:
			report = self.input()

			station_id = report['station_id']
			ip = report['IP']

			self.db_semaphore.acquire()		
			self.add(station_id,ip)
			self.db_semaphore.release()

	def add(self,st_id,ip):
		if st_id in self.db:
			if ip not in self.db[st_id]:
				self.db[st_id].append(ip)
		else:
			self.db[st_id] = [ip]

	def query_one(self,id):
		if id not in self.db:
			return None
		else:
			return random.choice(self.db[id])


class protocol_identification_table(ip_identification_table):
	def collect(self):
		while True:
			report = self.input()

			station_id = report['station_id']
			protocol = report['protocol']

			self.db_semaphore.acquire()		
			self.add(station_id,protocol)
			self.db_semaphore.release()

	def query(self,id):
		if id not in self.db:
			return []
		else:
			return self.db[id]


class network_list(object):
	def __init__(self,input):
		self.db = []
		self.input = input
		self.db_semaphore = threading.Semaphore()
	
		self.x=threading.Thread(target=self.collect)
		self.x.daemon=True
		self.x.start()

	def collect(self):
		while True:
			data = self.input()
			self.add(data['network'])

	def add(self,network):
		self.db_semaphore.acquire()
		temp_db = []
		for i in self.db:
			if not network.Contains(i):
				temp_db.append(i)

		for i in temp_db:
			if i.Contains(network):
				self.db = temp_db
				self.db_semaphore.release()
				return

		temp_db.append(network)
		self.db = temp_db
		self.db_semaphore.release()

	def dump(self):
		self.db_semaphore.acquire()
		retval = copy.copy(self.db)
		self.db_semaphore.release()
		return retval

