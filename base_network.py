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

from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

network_ = namedtuple("network", "address, netmask, port")


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
        self.discovery = hub.spawn(self._discover_topology)

    def _discover_topology(self):
        """
        This thread infinitely runs at a periodic interval 
        :return: 
        """
        while True:
            hub.sleep(TOPOLOGY_DISCOVERY_INTERVAL)
            self._discover_()
            self._dijkstra_shortest_path()
            print (self.__str__())
            #self._create_proactive_lsp()

    def _read_config_file(self, file_name=CONFIG_FILE):
        with open(file_name) as config:
            data = json.load(config)
            self.node_count = data[NODE_CT]
            for datapath in data[INGRESS]:
                self.ingress[int(datapath[DPID],16)] = [network_(net[ADDRESS], net[NETMASK], net[PORT])for net in datapath[NETWORK]]

            for datapath in data[EGRESS]:
                self.egress[int(datapath[DPID], 16)] = [network_(net[ADDRESS], net[NETMASK], net[PORT]) for net in datapath[NETWORK]]
        self._print_ingress_node()
        self._print_egress_node()

    def _print_ingress_node(self):
        print ("Node Ct in {0} = {1} ".format(CONFIG_FILE, self.node_count))
        print ("\nIngress datapaths:")
        for dpid, net in self.ingress.items():
            print ("DPID = {0}".format(dpid))
            for n in net:
                print ("[address: {0}, netmask: {1}, port={2}]".format(n.address, n.netmask, n.port), end="\t")
        print()

    def _print_egress_node(self):
        print ("\nEgress datapaths:")
        for dpid, net in self.egress.items():
            print ("DPID = {0}".format(dpid))
            for n in net:
                print ("[address: {0}, netmask: {1}, port={2}]".format(n.address, n.netmask, n.port), end="\t")
        print ()

    def _discover_(self):
        print ("Inside discovery")
        nodes = get_switch(self)
        #print (nodes)
        for node in nodes:
            if node.dp.id in self.datapaths:
                self.network.add_node(node.dp.id)
            else:
                print ("WARNING: node={0} not in self.datapaths. SKIPPED".format(node.dp.id))

        links = get_link(self)
        #print (links)
        for link in links.keys():
            if link.src.dpid in self.datapaths and link.dst.dpid in self.datapaths:
                self.network.add_edge(link.src.dpid, link.dst.dpid, WEIGHT=1, src_port=link.src.port_no, dst_port=link.dst.port_no)
            else:
                print ("WARNING: link.src={0} and link.dst={1} not in self.datapaths. SKIPPED".format(
                    link.src.dpid, link.dst.dpid))
        #pdb.set_trace()

    def _dijkstra_shortest_path(self):
        """
        For each combination of Ingress and Egress nodes find the shortest path.
        :return: None
        """
        #pdb.set_trace()
        print ("Inside dijkstra")
        for src, dst in product(self.ingress.keys(), self.egress.keys()):
            self.paths[(src, dst)] = nx.dijkstra_path(self.network, src, dst)
        for key, value in self.paths.items():
            print ("{0}  \t\t\t {1}".format(key, value))

    def _monitor_traffic(self):
        pass

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def add_arp_broadcast_rule(self,ev):
        datapath = ev.datapath  # Check this
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _base_network_change_handler(self, ev):
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
            self.add_arp_broadcast_rule(ev)

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
                try:
                    self.network.remove_node(datapath.id)
                except nx.exception.NetworkXError as ne:
                    print ("Node {0} was not in the network graph".format(datapath.id))

    def __str__(self):
        ret_str = "\nIngress Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.ingress])
        ret_str += "\n\nEgress Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.egress])
        ret_str += "\n\nDatapaths: int, \t\t hex \n\t"
        ret_str += "\t".join(["{0}\t{1}\n".format(str(dpid), str(hex(dpid))) for dpid in self.datapaths.keys()])
        ret_str += "\nEdge list:\n"
        ret_str += "\n".join(["(src={0}, {1}), (dst={2}, {3})".format(
            x,self.network[x][y]['src_port'],y, self.network[x][y]['dst_port']) for x,y in self.network.edges()])
        return ret_str

    def _create_proactive_lsp(self):
        """
        For each (src, dst) in self.paths
            Take a label Li
            At src:
                match= src, dst
                action = Push MPLS label Li, Output <port ?>
            At dest:
                match= MPLS label li, 
                action: Pop MPLS, output <port ?>
            At core nodes:
                match= MPLS label Li,
                action: output <prt ?>
        """
        for (src, dst), path in self.paths.items():
            src_dp = self.datapaths[src]
            dst_dp = self.datapaths[dst]

        pdb.set_trace()

    def _get_out_port(self, src_id, dst_id):
        pass

    def _add_rule(self, datapath, ):
        """
        
        """