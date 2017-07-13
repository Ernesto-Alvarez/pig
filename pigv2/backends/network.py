import threading
import ipaddr

class ip_subnet_calculator_by_distance(object):
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

		all_zeros = ipaddr.IPv4Network('0.0.0.0/0')
		invalid_masks = [ipaddr.IPv4Address('255.255.255.255'),ipaddr.IPv4Address('255.255.255.254'),ipaddr.IPv4Address('255.255.0.0'),ipaddr.IPv4Address('255.254.0.0'),ipaddr.IPv4Address('255.252.0.0'),ipaddr.IPv4Address('255.248.0.0'),ipaddr.IPv4Address('255.240.0.0'),ipaddr.IPv4Address('255.224.0.0'),ipaddr.IPv4Address('255.192.0.0'),ipaddr.IPv4Address('255.128.0.0'),ipaddr.IPv4Address('255.0.0.0'),ipaddr.IPv4Address('254.0.0.0'),ipaddr.IPv4Address('252.0.0.0'),ipaddr.IPv4Address('248.0.0.0'),ipaddr.IPv4Address('240.0.0.0'),ipaddr.IPv4Address('224.0.0.0'),ipaddr.IPv4Address('192.0.0.0'),ipaddr.IPv4Address('128.0.0.0'),ipaddr.IPv4Address('0.0.0.0')]

		while True:
			data = self.input()
			information = self.extract_info(data)
			if information['network'].netmask not in invalid_masks:
				self.output(information)

	def extract_info(self,data):
		ip1 = ipaddr.IPv4Network(data['source'])
		ip2 = ipaddr.IPv4Network(data['destination'])



		while ip1 != ip2:
			ip1 = ip1.Supernet()
			ip2 = ip2.Supernet()

		return {'network' : ip2.Supernet(prefixlen_diff=0)}

