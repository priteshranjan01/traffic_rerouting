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


class Lsp(object):
    def __init__(self, label=None, path=None):
        self.label = label
        self.path = path

    def __eq__(self, other):
        return set(self.path) == set(other.path)


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
        self.lsp_count = 0
        self.datapaths = {}  # Updated when a datapath connects/disconnects with the controller.
        self.lers = {}  # Label Edge Routers: (dpid) -> [(address, netmask, port)]
        self._read_config_file(CONFIG_FILE)
        # Directed graph because We need 2 labels for To and Fro path.
        self.network = nx.DiGraph()  # Updated every time _discover is called.
        self.paths = {}  # (src, dst) -> [(label, path)]
        self._initialize_empty_ingress_egress_path()
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
            self._create_proactive_lsp()

    def _read_config_file(self, file_name=CONFIG_FILE):
        with open(file_name) as config:
            data = json.load(config)
            self.node_count = data[NODE_CT]
            for datapath in data[LER]:
                self.lers[int(datapath[DPID],16)] = [network_(net[ADDRESS], net[NETMASK], net[PORT])for net in datapath[NETWORK]]

        self._print_edge_nodes()

    def _initialize_empty_ingress_egress_path(self):
        for src, dst in product(self.lers.keys(), self.lers.keys()):
            if src != dst:
                self.paths[(src, dst)] = []

    def _print_edge_nodes(self):
        print ("Node Ct in {0} = {1} ".format(CONFIG_FILE, self.node_count))
        print ("\nLabel Edge datapaths:")
        for dpid, net in self.lers.items():
            print ("DPID = {0}".format(dpid))
            for n in net:
                print ("[address: {0}, netmask: {1}, port={2}]".format(n.address, n.netmask, n.port), end="\t")
        print()

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
        for src, dst in product(self.lers.keys(), self.lers.keys()):
            if src != dst:
                new_lsp = Lsp(self.lsp_count, nx.dijkstra_path(self.network, src, dst))
                add_new_lsp = True
                for _, _lsp in self.paths.items():
                    if isinstance(_lsp, Lsp):
                        if _lsp == new_lsp:
                            add_new_lsp = False
                if add_new_lsp:
                    self.lsp_count += 1
                    self.paths[(src, dst)].append(new_lsp)
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
        match = parser.OFPMatch(eth_type=ARP)
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
            if datapath.id in self.lers:
                print ("Edge node dpid= {0} connected".format(datapath.id))
            else:
                print("Core node dpid= {0} connected".format(datapath.id))
            self.datapaths[datapath.id] = datapath
            self.add_arp_broadcast_rule(ev)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                if datapath.id in self.lers:
                    print("Edge node dpid= {0} disconnected".format(datapath.id))
                else:
                    print("Core node dpid= {0} disconnected".format(datapath.id))
                del self.datapaths[datapath.id]
                # Remove from network graph also.
                try:
                    self.network.remove_node(datapath.id)
                except nx.exception.NetworkXError as ne:
                    print ("Node {0} was not in the network graph".format(datapath.id))

    def __str__(self):
        ret_str = "\nEdge Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.lers])
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
        for (src, dst), lsps in self.paths.items():
            src_dp = self.datapaths[src]
            dst_dp = self.datapaths[dst]
            # In path A-B-C-D, src will be A and dst will D
            # For link A-B src_op_port is the port on A which connects to B
            # ip_dst
            for _lsp in lsps:
                path = _lsp.path
                label = _lsp.label
                # Set rule for ingress LER.
                src_op_port = self.network[src][path[1]]['src_port']
                # dst shall be D and src will
                ip_dst = getattr(self.lers[dst][0], ADDRESS)  # TODO: change hardcoded index.
                ip_src = getattr(self.lers[src][0], ADDRESS)
                # Add a rule to push MPLS label on the incoming traffic.
                parser = src_dp.ofproto_parser
                match = parser.OFPMatch(eth_type=IP, ipv4_src=ip_src, ipv4_dst=ip_dst)
                actions = [parser.OFPActionPushMpls(ethertype=MPLS),
                           parser.OFPActionSetField(mpls_label=label),
                           parser.OFPActionOutput(port=src_op_port)]
                self.add_flow(src_dp, 10, match, actions)
                print ("\nPushRule Added SUCCESS on DPID: {3}, \nMatch: Eth_type={0}, IP_src={1}, IP_dst={2}".format(IP, ip_src, ip_dst, src))
                print ("Action: Push MPLS label= {0}, out_port={1}\n".format(label, src_op_port))

                # Add rule to pop MPLS label at the Egress node.
                dst_out_port = getattr(self.lers[dst][0],PORT)
                parser = dst_dp.ofproto_parser
                match = parser.OFPMatch(eth_type=MPLS, mpls_label=label)
                actions = [parser.OFPActionPopMpls(ethertype=IP),
                           parser.OFPActionOutput(port=dst_out_port)]
                self.add_flow(dst_dp, 10, match, actions)
                print ("\nPopRULE ADDED SUCCESS DPID: {0}, Match: Eth_type={1}, MPLS label={2}".format(dst, MPLS, label))
                print ("Action: PoP MPLS label= {0}, out_port={1}\n".format(label, dst_out_port))

                # Now add rules for the network nodes.
                for i in range(1, len(path)-1):  # A-B-C-D-E-F. Add rules on B, C, D, E
                    link_src = path[i]
                    link_dst = path[i+1]
                    out_port = self.network[link_src][link_dst]['src_port']
                    link_src_dp = self.datapaths[link_src]
                    parser = link_src_dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=MPLS, mpls_label=label)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    self.add_flow(link_src_dp, 10, match, actions)
                    print ("\nMatchRule added Success: {0}, MPLS label={1}".format(link_src, label))
                    print ("Action: Out_port {0}".format(out_port))

    def _get_out_port(self, src_id, dst_id):
        pass
