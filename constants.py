# The topology discovery thread sleep duration
TOPOLOGY_DISCOVERY_INTERVAL = 10
# Traffic monitor thread sleep duration
TRAFFIC_MONITOR_INTERVAL = 10

# OVERLOAD_PERCENT controls when a port is considered as being overloaded.
# For example, if the average number of packets processed by the ports
# on switch S is X, then if a port P handles more than 1.2X packets, then
# X shall be considered as overloaded.
OVERLOAD_FACTOR = 0.2
CONFIG_FILE = "CONFIG.json"

# Key in CONFIG.json
NODE_CT = "node_ct"
LER = "edges"
DPID = "dpid"
NETWORK = "host"
ADDRESS = "address"
NETMASK = "netmask"
PORT = "port"

# weight is a special attribute used by networkx path calculation libraries
WEIGHT = "weight"
# Ether Type protocol numbers.
MPLS = 0x8847
ARP = 0x806
IP = 0x800
