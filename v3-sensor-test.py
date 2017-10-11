from pigv3.packet_mgmt import live_sensor
from pigv3.packet_mgmt import pcap_recorder
from pigv3.packet_mgmt import replay_sensor
from Queue import Queue
import time

q = Queue()
q2 = Queue()
q3 = Queue()
s = live_sensor(q.put,"wlp3s0")
r = pcap_recorder(q2.get,"/tmp/x.pcap")

print "=================LIVE======================"

packet = q.get()
ts_stop = time.time() + 5
while packet['type'] != 'Capture End':
	q2.put(packet)
	print packet
	if time.time() > ts_stop:
		packet = { 'type' : 'Capture End' }
	else:
		packet = q.get()
r.kill()

print "==================REPLAY===================="


p = replay_sensor(q3.put,"/tmp/x.pcap",replay_speed=1,repetitions=1)
packet = q3.get()
while packet['type'] != 'Capture End':
	print packet
	packet = q3.get()
