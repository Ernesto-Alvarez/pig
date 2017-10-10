#Sensors are responsible for
# 1. Detecting specific traffic and providing traffic data (e.g. source, destination, etc)
# 2. Eliminating/filtering false detections
# 3. Converting impacket's weird formats to standard forms (e.g. ipaddr/macaddress)

#Backends are responsible for
# 1. "Thinking": from one or more packets sent by sensors, deducing meaningful information (like whether a host is present on a network, or what is the IP network range)
# 2. Forwarding information from item 1 to a storage database, without unnecessary clutter

#Databases are responsible for
# 1. Providing tables, trees, etc to securely store detection data
# 2. Providing concurrent access to data

#Auxiliary modules provide functions that are not part of the processing chain but are useful/needed
# Right now it provides addressing (to standardize address formats within the library) and a reference database to help interfaces resolve OUIs from MAC addresses.

#Glue items join everything else (not in use right now)