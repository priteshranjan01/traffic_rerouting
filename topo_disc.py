from __future__ import print_function

import json
import pdb
from itertools import product

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link


TOPOLOGY_DISCOVERY_INTERVAL=20
CONFIG_FILE="CONFIG.json"
EGRESS="egress"
INGRESS="ingress"
NODE_CT="node_ct"
WEIGHT="weight"


class BaseNetwork(app_manager.RyuApp):
    """
    The Network class which keeps network topology, datapath status,
    finds shortest path between Ingress and Egress nodes and collects 
    network statistics.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs ):
        """
        Initialize an empty dictionary to keep datapath objects.
        Start the network topology discovery routine to run at constant interval.
        Start the network traffic monitoring routine.
        """
        super(BaseNetwork, self).__init__(*args, **kwargs)
        self.name = "BaseNetwork"
        self.node_count = 0
        self.datapaths = {}  # Updated when a datapath connects/disconnects with the controller.
        self.ingress = set()  # Read in from CONFIG_FILE
        self.egress = set()  # Read in from CONFIG_FILE
        self._read_config_file(CONFIG_FILE)
        self.network = nx.Graph()  # Updated every time _discover is called.
        self.paths = {}  # (src, dst) -> path_list
        self.discovery = hub.spawn(self._discover_topology)

    def _read_config_file(self, file_name=CONFIG_FILE):
        with open(file_name) as config:
            config_data = json.load(config)
            self.node_count = config_data[NODE_CT]
            self.ingress = set([int(x['id'],16) for x in config_data[INGRESS]])
            self.egress = set([int(x['id'], 16) for x in config_data[EGRESS]])

        print ("{0} Nodes".format(self.node_count))
        print ("Ingress datapaths:")
        for sw in self.ingress:
            print (sw)
        print ("Egress datapaths:")
        for sw in self.egress:
            print (sw)

    def _discover_topology(self):
        """
        This thread infinitely runs at a periodic interval 
        :return: 
        """
        while True:
            hub.sleep(TOPOLOGY_DISCOVERY_INTERVAL)
            self._discover()
            self._run_dijkstra_shortest_path()

    def _discover(self):
        nodes = get_switch(self)
        for node in nodes:
            if node.dp.id in self.datapaths:
                self.network.add_node(node.dp.id)
            else:
                print ("WARNING: node={0} not in self.datapaths. SKIPPED".format(node.dp.id))

        links = get_link(self)
        for link in links.keys():
            if link.src.dpid in self.datapaths and link.dst.dpid in self.datapaths:
                self.network.add_edge(link.src.dpid, link.dst.dpid, WEIGHT=1)
            else:
                print ("WARNING: link.src={0} and link.dst={1} not in self.datapaths. SKIPPED".format(
                    link.src.dpid, link.dst.dpid))

    def _run_dijkstra_shortest_path(self):
        """
        For each combination of Ingress and Egress nodes find the shortest path.
        :return: None
        """
        for src, dst in product(self.ingress, self.egress):
            self.paths[(src, dst)] = nx.dijkstra_path(self.network, src, dst)
        for key, value in self.paths.items():
            print ("{0}  \t\t\t {1}".format(key, value))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _datapath_state_change_handler(self, ev):
        """
        Add/Remove datapath objects to/from the datapath dictionary 
        Source: Adapted from Ryubook section 3.2
        """
        # pdb.set_trace()
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id in self.ingress:
                print ("Ingress node dpid= {0} connected".format(hex(datapath.id)))
            elif datapath.id in self.egress:
                print("Egress node dpid= {0} connected".format(hex(datapath.id)))
            else:
                print("Added dpid {0}".format(hex(datapath.id)))
            self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                if datapath.id in self.ingress:
                    print("Ingress node dpid= {0} disconnected".format(hex(datapath.id)))
                elif datapath.id in self.egress:
                    print ("Egress node dpid= {0} disconnected".format(hex(datapath.id)))
                else:
                    print("Removed dpid {0}".format(hex(datapath.id)))
                del self.datapaths[datapath.id]
