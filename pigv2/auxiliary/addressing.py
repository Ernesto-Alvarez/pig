class ieee_assignment(object):
	def __init__(self,address):
		#Acceptable formats: string, list of octets or strings

		self.address = self.format_interpreter(address)



	def format_interpreter(self,address):

		if type(address) == type(list()):		#Need to iterate on all items and obtain a reasonable string representation
			temp_address = ""
			for i in address:
				if type(i) == type(int()):
					if i > 255:
						raise TypeError("Address component out of bounds")

					temp_address = temp_address + "%02X" % i 

				elif type(i) == type(str()):
					temp_address = temp_address + i
			address = temp_address

		if type(address) != type(str()):		
			raise TypeError("Unable to understand address format")

		address = address.translate(None,":-")
		address = address.upper()		

		if len(address) > 12:
			raise TypeError("Address is too long to be a mac address")

		for i in address:
			if i not in "ABCDEF0123456789":
				raise TypeError("Unknown characters in address")
		return address

	def up(self):
		if self.address == "":
			return self.address

		return ieee_assignment(self.address[:-1])

	def root(self):
		return self.address == ""

	def __hash__(self):
		return self.address.__hash__()

	def __repr__(self):
		return self.address

	def __eq__(self,other):
		return self.address == other.address

	def __ne__(self,other):
		return self.address != other.address

	def __gt__(self,other):
		if len(self.address) >= len(other.address):
			return False
		return self.address == other.address[0:len(self.address)]

	def __lt__(self,other):
		if len(self.address) <= len(other.address):
			return False
		return other.address == self.address[0:len(other.address)]

	def __le__(self,other):
		if len(self.address) < len(other.address):
			return False
		return other.address == self.address[0:len(other.address)]

	def __ge__(self,other):
		if len(self.address) > len(other.address):
			return False
		return self.address == other.address[0:len(self.address)]

class mac_address(ieee_assignment):
	def __init__(self,address):
		str_address = self.format_interpreter(address)
		if len(str_address) != 12:
			raise TypeError("Incorrect length for MAC address")
		self.address = str_address

	def __str__(self):
		return self.address[0:2] + ":" + self.address[2:4] + ":" + self.address[4:6] + ":" + self.address[6:8] + ":" + self.address[8:10] + ":" + self.address[10:12]

#IP addresses are handled by Google's ipaddr module

