from __future__ import print_function

from constants import *

import json
import pdb
from itertools import product
from collections import namedtuple

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

network_ = namedtuple("network", "address, netmask")


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
        self.ingress = {}  # Read in from CONFIG_FILE
        self.egress = {}  # Read in from CONFIG_FILE
        self._read_config_file(CONFIG_FILE)
        self.network = nx.Graph()  # Updated every time _discover is called.
        self.paths = {}  # (src, dst) -> path_list

    def _read_config_file(self, file_name=CONFIG_FILE):
        with open(file_name) as config:
            data = json.load(config)
            self.node_count = data[NODE_CT]
            for datapath in data[INGRESS]:
                self.ingress[int(datapath[DPID],16)] = [network_(net[ADDRESS], net[NETMASK])for net in datapath[NETWORK]]

            for datapath in data[EGRESS]:
                self.egress[int(datapath[DPID], 16)] = [network_(net[ADDRESS], net[NETMASK]) for net in datapath[NETWORK]]
        self._print_ingress_node()
        self._print_egress_node()

    def _print_ingress_node(self):
        print ("Node Ct in {0} = {1} ".format(CONFIG_FILE, self.node_count))
        print ("Ingress datapaths:")
        for dpid, net in self.ingress.items():
            print ("\nDPID = {0}".format(dpid))
            for n in net:
                print ("[address: {0}, netmask: {1}]".format(n.address, n.netmask), end="\t")
        print()

    def _print_egress_node(self):
        print ("Egress datapaths:")
        for dpid, net in self.egress.items():
            print ("\nDPID = {0}".format(dpid))
            for n in net:
                print ("[address: {0}, netmask: {1}]".format(n.address, n.netmask), end="\t")

    def _discover_(self):
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

    def _dijkstra_shortest_path(self):
        """
        For each combination of Ingress and Egress nodes find the shortest path.
        :return: None
        """
        for src, dst in product(self.ingress.keys(), self.egress.keys()):
            self.paths[(src, dst)] = nx.dijkstra_path(self.network, src, dst)
        for key, value in self.paths.items():
            print ("{0}  \t\t\t {1}".format(key, value))

    def _monitor_traffic(self):
        pass

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
                print ("Ingress node dpid= {0} connected".format(datapath.id))
            elif datapath.id in self.egress:
                print("Egress node dpid= {0} connected".format(datapath.id))
            else:
                print("Core node dpid= {0} connected".format(datapath.id))
            self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                if datapath.id in self.ingress:
                    print("Ingress node dpid= {0} disconnected".format(datapath.id))
                elif datapath.id in self.egress:
                    print ("Egress node dpid= {0} disconnected".format(datapath.id))
                else:
                    print("Core node dpid= {0} disconnected".format(datapath.id))
                del self.datapaths[datapath.id]
                # Remove from network graph also.
                self.network.remove_node(datapath.id)

    def __str__(self):
        ret_str = "\nIngress Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.ingress])
        ret_str += "\n\nEgress Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.egress])
        ret_str += "\n\nDatapaths: int, \t\t hex \n\t"
        ret_str += "\t".join(["{0}\t{1}\n".format(str(dpid), str(hex(dpid))) for dpid in self.datapaths.keys()])
        ret_str += "\nEdge list:\n"
        ret_str += "\n".join(["src={0}, dst={1}".format(x,y) for x,y in self.network.edges()])
        return ret_str
