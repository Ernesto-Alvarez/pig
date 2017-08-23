
#####
##### 
##### Run me as
#####   python pigv2.py <interface>
#####
#####


from pigv2.sensors import ethernet_sensor
from pigv2.sensors import l3_protocol_sensor
from pigv2.auxiliary.reference import mac_address_database as oui_database
from pigv2.auxiliary.reference import ethertype_database as et_database
from pigv2.backends.detection import source_detector
import datetime
import time
import Queue
import os

from pigv2.databases import station_detection_table as station_table
from pigv2.databases import ip_identification_table
from pigv2.databases import protocol_identification_table

from pigv2.sensors import ip_sensor
from pigv2.sensors import ip_local_bcast_sensor
from pigv2.sensors import ip_local_multicast_sensor
from pigv2.sensors import ip_directed_bcast_sensor
from pigv2.sensors import arp_sensor

from pigv2.backends.identification import ip_identifier
from pigv2.backends.glue import hub
from pigv2.backends.glue import network_range_gate
from pigv2.backends.network import ip_subnet_calculator_by_distance as subcal
from pigv2.databases import network_list

def clear():
	os.system('clear')
	return

def init(interface='enp0s31f6'):
	sensor_queue = Queue.Queue()
	sensor = ethernet_sensor(sensor_queue.put, interface)
	backend_queue = Queue.Queue()
	detector = source_detector(sensor_queue.get,backend_queue.put)
	station_list = station_table(backend_queue.get)
	
	
	protocol_id_queue = Queue.Queue()
	protocol_id_sensor = l3_protocol_sensor(protocol_id_queue.put, interface)
	protocol_table = protocol_identification_table(protocol_id_queue.get)
	
	
	ip_sensor_queue = Queue.Queue()
	ip_backend_queue = Queue.Queue()
	
	ip_table = ip_identification_table(ip_backend_queue.get)
	
	ip_s1 = ip_local_bcast_sensor(ip_sensor_queue.put, interface)
	ip_s2 = ip_local_multicast_sensor(ip_sensor_queue.put, interface)
	ip_s3 = ip_directed_bcast_sensor(ip_sensor_queue.put, interface)
	ip_s4 = arp_sensor(ip_sensor_queue.put, interface)
	
	ipid_sensor_queue = Queue.Queue()
	ipnet_sensor_queue = Queue.Queue()
	ipnet_backend_queue = Queue.Queue()
	
	ip_hub = hub(ip_sensor_queue.get,[ipid_sensor_queue.put,ipnet_sensor_queue.put])
	
	ip_backend = ip_identifier(ipid_sensor_queue.get,ip_backend_queue.put)
	subnet_calculator = subcal(ipnet_sensor_queue.get,ipnet_backend_queue.put)
	networks = network_list(ipnet_backend_queue.get)
	
	uip_sensor_queue = Queue.Queue()
	uip_sensor = ip_sensor(uip_sensor_queue.put, interface)
	uip_gate = network_range_gate(uip_sensor_queue.get,ipid_sensor_queue.put,networks.dump)
	
	
	etype_db = et_database()
	oui_db = oui_database()

	while True:
		clear()
		now = datetime.datetime.utcnow()
		stations = station_list.dump()
		
		print 'Network list'
		nets = networks.dump()
		for i in nets:
			print i
		
		print ''
		print 'Station list'
		print '{0:18} {1:17} {2:25} {3:10} {4:20}'.format('MAC Address', 'IP', 'Manufacturer' ,'Last seen', 'Protocols')
		for i in stations:
			last_seen = abs(now - stations[i])
			td = str(last_seen)
			if ',' not in td:
				last_seen_printable = td.split('.')[0]
			else:
				last_seen_printable = td.split(',')[0]
			manufacturer = oui_db.search(i)
			protocols = []
			for j in protocol_table.query(i):
				protocols.append(etype_db.query(j))
	
			if protocols == []:
				protocols_text = ""
			else:
				protocols_text = reduce(lambda x,y: x+","+y,protocols)
		
	
			print '{0:18} {1:17} {2:25} {3:10} {4:20}'.format(i, str(ip_table.query_one(i)), str(manufacturer)[:25],last_seen_printable.rjust(8),protocols_text[:20])
                #uip_gate.debug_data()
		time.sleep(1)

if __name__ == '__main__':
	import sys
	if len(sys.argv) != 2:
		print 'Usage:  %s <interface>' % sys.argv[0]
		sys.exit(1)
	init(sys.argv[1])
