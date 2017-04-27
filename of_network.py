from __future__ import print_function, division

from constants import *

import networkx as nx

import json
import pdb
from collections import namedtuple
from itertools import product

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import OFPP_MAX
from ryu.ofproto.ofproto_v1_3 import OFPFC_DELETE, OFPG_ANY, OFPFF_RESET_COUNTS
from ryu.ofproto.ofproto_v1_3_parser import OFPActionOutput

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link


network_ = namedtuple("network", "address, netmask, port")
port_ = namedtuple("port", "number, weight")
flow_ = namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")


class OfNetwork(app_manager.RyuApp):
    """
    Class: OpenFlow Network
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs ):
        """
        Initialize an empty dictionary to keep datapath objects.
        Start the network traffic monitoring routine.
        """
        super(OfNetwork, self).__init__(*args, **kwargs)
        self.REPEAT_TOPOLOGY_DISCOVERY = True
        self.name = "OfNetwork"
        self.node_count = 0
        self.connected_node_ct = 0

        self.datapaths = {}
        self.dp_stats = {}  # {DPID -> port_}
        self.dp_overload_ports = {}  # {DPID -> [port_no]}
        self.dp_flows = {}  # {DPID -> 5_tuple_flow_keys}
        self.edges = {}  # Edge nodes  {DPID -> network_}
        self.victim_nodes = set()  # The nodes not be considered in path calculation
        # Directed graph because We need 2 labels for To and Fro path.
        self.network = nx.DiGraph()  # Updated when _discover is called.
        self.paths = {}  # (src, dst) -> [(label, path)]
        self.discovery_thread = None
        self.monitor_thread = None
        self._read_config_file(CONFIG_FILE)

    def _read_config_file(self, file_name=CONFIG_FILE):
        with open(file_name) as config:
            data = json.load(config)
            self.node_count = data[NODE_CT]
            for datapath in data[LER]:
                self.edges[int(datapath[DPID], 16)] = [
                    network_(net[ADDRESS], net[NETMASK], net[PORT])for net in datapath[NETWORK]]

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _network_state_change(self, ev):
        """
        Add/Remove datapath objects to/from the datapath dictionary 
        Source: Adapted from Ryubook section 3.2
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id in self.edges:
                print ("Edge node dpid= {0} connected".format(datapath.id))
            else:
                print("Core node dpid= {0} connected".format(datapath.id))
            self.datapaths[datapath.id] = datapath
            self.dp_stats[datapath.id] = {}
            self.dp_overload_ports[datapath.id] = {}
            self.dp_flows[datapath.id] = set()
            # Delete all flows (of eth_type == IP)
            self._delete_all_flows(datapath)
            # Add ARP broadcast rule
            self._add_arp_broadast_rule(datapath)
            self.connected_node_ct += 1
            if self.connected_node_ct == self.node_count:
                # All datapaths have connected. Start topology discovery
                self.discovery_thread = hub.spawn(self._discover_topology)
                # TODO: Start traffic monitor thread.

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.edges:
                print("Edge node dpid= {0} disconnected".format(datapath.id))
            else:
                print("Core node dpid= {0} disconnected".format(datapath.id))
            del self.datapaths[datapath.id]
            del self.dp_stats[datapath.id]
            del self.dp_overload_ports[datapath.id]
            del self.dp_flows[datapath.id]
            try:
                self.network.remove_node(datapath.id)
            except nx.exception.NetworkXError as ne:
                print ("Node {0} was not in the network graph".format(datapath.id))
            self.connected_node_ct -= 1

    def _monitor_traffic(self):
        """
        Get port data for each switch in the network.
        """
        while True:
            hub.sleep(TRAFFIC_MONITOR_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY == False:  # When the nework is stable
                for dp in self.datapaths.values():
                    # TODO: Request Port stats.
                    pass

    def _install_proactive_flows(self):
        """
        For each (datapath, edge)
            Find the out_port at the datapath. (port connecting the next hop)
            Add a rule with:
                match = edge IP address.
                action = output at out_port
        """
        for (src, edge), path in self.paths.items():
            ip_dst = getattr(self.edges[edge][0], ADDRESS)
            src_out_port = self.network[src][path[1]]['src_port']
            src_dp = self.datapaths[src]
            parser = src_dp.ofproto_parser
            match = parser.OFPMatch(eth_type=IP, ipv4_dst=ip_dst)
            actions = [parser.OFPActionOutput(port=src_out_port)]
            self._add_flow(src_dp, priority=10, match=match, actions=actions)
            print ("{0} SUCCESS Rule, match=(IP Dst={1}), Action=(output:{2})".format(
                src_dp.id, ip_dst, src_out_port))

        # At each edge node, install rule to forward traffic to host.
        for edge, nets in self.edges.items():
            for net in nets:
                out_port = net.port
                ip_dst = net.address
                dp = self.datapaths[edge]
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=IP, ipv4_dst=ip_dst)
                actions = [parser.OFPActionOutput(port=out_port)]
                self._add_flow(dp, priority=10, match=match, actions=actions)
                print ("{0} SUCCESS Rule, match=(IP Dst={1}), Action=(output:{2})".format(
                    dp.id, ip_dst, out_port))

    def _discover_topology(self):
        while True:
            hub.sleep(TOPOLOGY_DISCOVERY_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY:
                self.REPEAT_TOPOLOGY_DISCOVERY = False
                # Start discover
                self._discover_()
                # Run Dijkstra. Find the shortest path from each datapath to each edge
                self._dijkstra_shortest_path()
                self._install_proactive_flows()

    def _dijkstra_shortest_path(self):
        print ("Inside Dijkstra")
        print (self.__str__())
        #pdb.set_trace()
        for src, dst in product(self.datapaths, self.edges):
            if src != dst:
                path = nx.dijkstra_path(self.network, src, dst)
                self.paths[(src, dst)] = path
        for key, value in self.paths.items():
            print ("{0} \t {1}".format(key, value))

    def _discover_(self):
        print ("Inside discovery")
        nodes = get_switch(self)
        for node in nodes:
            print (node)
            if node.dp.id in self.datapaths:
                self.network.add_node(node.dp.id)
            else:
                print ("WARNING: node={0} not in self.datapaths. SKIPPED".format(node.dp.id))
        links = get_link(self)
        for link in links.keys():
            print("src= {0} dst = {1}".format(link.src, link.dst))
            if link.src.dpid in self.datapaths and link.dst.dpid in self.datapaths:
                self.network.add_edge(link.src.dpid, link.dst.dpid, WEIGHT=1, src_port=link.src.port_no, dst_port=link.dst.port_no)
            else:
                print ("WARNING: link.src={0} and link.dst={1} not in self.datapaths. SKIPPED".format(
                    link.src.dpid, link.dst.dpid))

    def _add_arp_broadast_rule(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, priority=1, match=match, actions=actions)

    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                flags=OFPFF_RESET_COUNTS, instructions=inst)
        datapath.send_msg(mod)

    def _delete_all_flows(self, datapath):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=IP)
        self._del_flow(datapath, match)

    def _del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # TODO : Forgot priority ?
        mod = parser.OFPFlowMod(datapath, command=OFPFC_DELETE,
                                buffer_id=ofproto.OFPCML_NO_BUFFER, out_port=ofproto.OFPP_ANY,
                                out_group=OFPG_ANY, match=match, instructions=[])
        datapath.send_msg(mod)

    def __str__(self):
        ret_str = "\nEdge Nodes:\n"
        ret_str += "\t".join([str(node) for node in self.edges])
        ret_str += "\n\nDatapaths: int, \t\t hex \n\t"
        ret_str += "\t".join(["{0}\t{1}\n".format(str(dpid), str(hex(dpid))) for dpid in self.datapaths])
        ret_str += "\nEdge list:\n"
        ret_str += "\n".join(["(src={0}, {1}), (dst={2}, {3})".format(
            x,self.network[x][y]['src_port'],y, self.network[x][y]['dst_port']) for x,y in self.network.edges()])
        return ret_str
