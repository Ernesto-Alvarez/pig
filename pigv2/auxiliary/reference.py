import csv
import os
resource_path = os.path.split(__file__)[0]
from pigv2.auxiliary.addressing import ieee_assignment

class mac_address_database():
	def __init__(self,filename=None):
		self.MAL = {}
		self.MAM = {}
		self.MAS = {}
		if filename != None:
			self.load_csv(filename)
		else:
			self.load_csv(os.path.join(resource_path,"macaddress.csv"))

	def load_csv(self,filename):
		with open(filename) as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				assignment = ieee_assignment(row[1])
				organization = row[2]
				if row[0] == "MA-L":
					self.MAL[assignment] = organization
				elif row[0] == "MA-M":
					self.MAM[assignment] = organization	
				elif row[0] == "MA-S":
					self.MAS[assignment] = organization

	def search_exact(self,assignment):

		if assignment in self.MAS:
			return self.MAS[assignment]
		elif assignment in self.MAM:
			return self.MAM[assignment]
		elif assignment in self.MAL:
			return self.MAL[assignment]
		else:
			return None

	def search(self,assignment):
		retval = None
		while retval == None and not assignment.root():
			retval = self.search_exact(assignment)
			assignment = assignment.up()
		return retval

class ethertype_database(object):
	def __init__(self):
		self.db = {34525 : 'IPv6', 2048 : 'IPv4' , 2054 : 'ARP', 66 : 'STP', 36864 : 'CTP', 8192 : 'CDP', 33011 : 'AARP', 32923 : 'AppleTalk', 34958 : 'EAPOL', 34915 : 'PPPOE-DISC'}

	def query(self,request):
		if request not in self.db:
			return str(request)
		else:
			return self.db[request]

	