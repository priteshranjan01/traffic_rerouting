from __future__ import print_function, division

from ryu.ofproto.ofproto_v1_3 import OFPFC_DELETE, OFPG_ANY, OFPFF_RESET_COUNTS
from ryu.ofproto.ofproto_v1_3_parser import OFPActionOutput

from constants import *

import json
import pdb
from collections import namedtuple
from itertools import product

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import OFPP_MAX

from ryu.lib import hub
from ryu.lib.packet import packet, ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, tcp, udp, icmp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

network_ = namedtuple("network", "address, netmask, port")
port_ = namedtuple("port", "number, weight")
flow_ = namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")
Lsp = namedtuple("Lsp", "label, path")

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
        self.REPEAT_TOPOLOGY_DISCOVERY = True
        self.name = "BaseNetwork"
        self.node_count = 0
        self.connected_node_ct = 0
        self.lsp_count = 0
        self.datapaths = {}  # Updated when a datapath connects/disconnects with the controller.
        self.dp_stats = {}  # Updated when controller collects datapath statistics
        self.dp_overload_ports = {}  # DPID -> [ports]
        self.flow_stats = {}  # DPID -> [(IP_proto, SRC_IP, DST_IP, SRC_PORT, DST_PORT)]
        self.lers = {}  # Label Edge Routers: (dpid) -> [(address, netmask, port)]
        self._read_config_file(CONFIG_FILE)
        self.victim_nodes = set()
        # Directed graph because We need 2 labels for To and Fro path.
        self.network = nx.DiGraph()  # Updated when _discover is called.
        self.paths = {}  # (src, dst) -> [(label, path)]
        self._initialize_empty_ingress_egress_path()
        self.discovery_thread = None
        self.monitor_thread = None

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
        print (nodes)
        for node in nodes:
            if node.dp.id in self.datapaths:
                self.network.add_node(node.dp.id)
            else:
                print ("WARNING: node={0} not in self.datapaths. SKIPPED".format(node.dp.id))

        links = get_link(self)
        print ("Links {0}".format(links))
        for link in links.keys():
            print("src= {0} dst = {1}".format(link.src, link.dst))
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
        #pdb.set_trace()
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
        """
        Get port data for each switch in the network.
        At each switch, if  
        """
        while True:
            hub.sleep(TRAFFIC_MONITOR_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY == False:  # When the nework is stable
                for dp in self.datapaths.values():
                    # self._request_flow_stats(dp)
                    self._request_port_stats(dp)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        print ("Sending Flow stats request to dpid {0}".format(datapath.id))
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #self.dp_overload_ports self.victim_nodes
        print ("Received flow stats reply from datapath {0}".format(datapath.id))
        #self.clear_all_stats(datapath)
        print ("Cleared all stats on dpid {0}".format(datapath.id))
        # pdb.set_trace()
        for stat in body:
            # clear the stats data from the datapath
            #self.clear_stats(datapath, match=stat.match, inst=stat.instructions)
            # Check if this flow stat is for one of the overloaded port
            for ac in stat.instructions:
                for action in ac.actions:
                    if isinstance(action, OFPActionOutput):
                        if action.port in self.dp_overload_ports[datapath.id]:
                            match = stat.match
                            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                            mod = parser.OFPFlowMod(datapath=datapath, priority=MAX_PRIORITY, match=match,
                                                    flags=OFPFF_RESET_COUNTS, hard_timeout=HARD_TIMEOUT,
                                                    instructions=inst)
                            #datapath.send_msg(mod)
                            print ("Dpid {0} match: {1} Send to CONTROLLER".format(datapath.id, match))
        # pdb.set_trace()

    def _request_port_stats(self, dp):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        req = parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY)
        dp.send_msg(req)
        print ("Sending port stats request to {0}".format(dp.id))

    def _port_weight(self, stat):
        # Simply returns tx.packets
        return stat.tx_packets

    def _average_weight(self, port_weight):
        try:
            wts = [wt for pt, wt in port_weight.items() if wt != 0 and pt < OFPP_MAX]
            avg = sum(wts)/len(wts)
            print ("WEIGHTS = {0}, average={1}".format(wts, avg))
            return avg
        except ZeroDivisionError:
            # TODO: Decide what to do when the stats received was empty
            print ("ZeroDivision ERROR")
            return 0

    def _overloaded_ports(self, dpid):
        avg_wt = self._average_weight(self.dp_stats[dpid])
        ov = [port for port, weight in self.dp_stats[dpid].items() if weight > (OVERLOAD_FACTOR + 1) * avg_wt]
        print ("Overloaded ports on dpid: {0} = {1}".format(dpid, ov))
        return ov

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        for port_stat in body:
            weight = self._port_weight(port_stat)
            # We overwrite past stats
            self.dp_stats[datapath.id][port_stat.port_no] = weight
            print("dpid = {0}, port_no={1}, weight={2}".format(datapath.id,port_stat.port_no, self.dp_stats[datapath.id][port_stat.port_no]))
        overloaded_ports = self._overloaded_ports(datapath.id)
        self.dp_overload_ports[datapath.id] = overloaded_ports

        for dst, ports in self.network.adj[datapath.id].items():
            if ports['src_port'] in overloaded_ports:
                self.victim_nodes.add(dst)

        print ("Victim Nodes = {0}".format(self.victim_nodes))

        # Request flow stats for this datapath
        self._request_flow_stats(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        datapath = msg.datapath
        if eth.ethertype != ether_types.ETH_TYPE_IP and eth.ethertype != ether_types.ETH_TYPE_MPLS:
            #print ("Dpid {0} packet ether type {1}".format(datapath.id, eth.ethertype))
            return
        if eth.ethertype == ether_types.ETH_TYPE_MPLS:
            print ("Received MPLS packet from datapath {0}".format(datapath.id))
            pdb.set_trace()
        else:
            print ("Received IPV4 packet from datapath {0}".format(datapath.id))
            #pdb.set_trace()
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == 1 :
                # ICMP
                icmp_packet = pkt.get_protocols(icmp.icmp)[0]
            elif ip.proto == 4:
                tcp_ = pkt.get_protocols(tcp.tcp)[0]
                self.flow_stats[datapath.id].add(flow_(4, ip.src, ip.dst, tcp_.src_port, tcp_.dst_port))
            elif ip.proto == 17:
                # TCP or UDP
                # namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")
                udp_ = pkt.get_protocols(udp.udp)[0]
                self.flow_stats[datapath.id].add(flow_(17, ip.src, ip.dst, udp_.src_port, udp_.dst_port))
        print ("Flow stats for dpid {0} = {1}".format(datapath.id, self.flow_stats[datapath.id]))


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                flags=OFPFF_RESET_COUNTS, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath, command=OFPFC_DELETE, priority=10,
                                buffer_id=ofproto.OFPCML_NO_BUFFER, out_port=ofproto.OFPP_ANY,
                                out_group=OFPG_ANY, match=match, instructions=[])
        datapath.send_msg(mod)

    def del_all_flows(self, datapath):
        parser = datapath.ofproto_parser
        # Delete the MPLS flows
        match = parser.OFPMatch(eth_type=MPLS)
        self.del_flow(datapath, match)

        # Delete the IP flows
        match = parser.OFPMatch(eth_type=IP)
        self.del_flow(datapath, match)

    def clear_stats(self, datapath, match, inst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_MODIFY, flags=OFPFF_RESET_COUNTS,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_arp_broadcast_rule(self,ev):
        datapath = ev.datapath  # Check this
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)

    def _discover_topology(self):
        """
        This thread infinitely runs at a periodic interval 
        :return: 
        """
        while True:
            hub.sleep(TOPOLOGY_DISCOVERY_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY:
                self._discover_()
                self._dijkstra_shortest_path()
                print(self.__str__())
                self._create_proactive_lsp()
                self.REPEAT_TOPOLOGY_DISCOVERY = False
                #self._monitor_traffic()
                #print ("Going to KILL thread {0}".format(self.discovery))
                #hub.kill(self.discovery)
                #print ("KILLED thread {0}".format(self.discovery))

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
            self.dp_stats[datapath.id] = {}
            self.dp_overload_ports[datapath.id] = {}
            self.flow_stats[datapath.id] = set()
            self.del_all_flows(datapath)
            self.add_arp_broadcast_rule(ev)
            self.connected_node_ct += 1
            if self.connected_node_ct == self.node_count:
                self.discovery_thread = hub.spawn(self._discover_topology)
                self.monitor_thread = hub.spawn(self._monitor_traffic)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                if datapath.id in self.lers:
                    print("Edge node dpid= {0} disconnected".format(datapath.id))
                else:
                    print("Core node dpid= {0} disconnected".format(datapath.id))
                del self.datapaths[datapath.id]
                del self.dp_stats[datapath.id]
                del self.dp_overload_ports[datapath.id]
                del self.flow_stats[datapath.id]
                # Remove from network graph also.
                try:
                    self.network.remove_node(datapath.id)
                except nx.exception.NetworkXError as ne:
                    print ("Node {0} was not in the network graph".format(datapath.id))
                self.connected_node_ct -= 1

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
