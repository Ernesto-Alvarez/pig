from pigv3.sensors import live_sensor
from pigv3.sensors import pcap_recorder
from pigv3.sensors import replay_sensor
from Queue import Queue
import time


q = Queue()
#s = live_sensor(q.put,"wlp3s0")
#r = pcap_recorder(q.get,"/tmp/x.pcap")
p = replay_sensor(q.put,"/tmp/x.pcap",timing_multiplier=100)

time.sleep(20)

