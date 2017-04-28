from __future__ import print_function, division

import pdb

from constants import *

import networkx as nx

import json
# import pdb
from collections import namedtuple
from itertools import product

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ether_types, in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3 import OFPP_MAX
from ryu.ofproto.ofproto_v1_3 import OFPFC_DELETE, OFPG_ANY, OFPFF_RESET_COUNTS
from ryu.ofproto.ofproto_v1_3_parser import OFPActionOutput

# from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link


network_ = namedtuple("network", "address, netmask, port")
port_ = namedtuple("port", "number, weight")
flow_ = namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")
port_stats_ = namedtuple("port_stats", "rx, tx, rx_err, tx_err")

class OfNetwork(app_manager.RyuApp):
    """
    Class: OpenFlow Network
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
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
        self.dp_flows = {}  # {DPID -> set(5_tuple_flow_keys)}
        self.edges = {}  # Edge nodes  {DPID -> network_}
        self.neglect_nodes = {}  # nodes not considered in path calculation. {DPID -> set()}
        # Directed graph because We need 2 labels for To and Fro path.
        self.network = None  # Updated when _discover is called.
        self.paths = {}  # (src, dst) -> [(label, path)]
        self.dp_port_stats = {}  # dpid -> {port -> port_stats}
        self.dp_port_stats_diff = {}  # dpid -> {port -> port_stats}
        self.discovery_thread = None
        self.monitor_thread = None
        self.analyzer_thread = None
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
            self.dp_port_stats[datapath.id] = {}
            self.dp_port_stats_diff[datapath.id] = {}
            self.dp_overload_ports[datapath.id] = {}
            self.dp_flows[datapath.id] = set()
            self.neglect_nodes[datapath.id] = set()
            # Delete all flows (of eth_type == IP)
            self._delete_all_flows(datapath)
            # Add ARP broadcast rule
            self._add_arp_broadcast_rule(datapath)
            self.connected_node_ct += 1
            if self.connected_node_ct == self.node_count:
                # All datapaths have connected. Start topology discovery
                self.network = nx.DiGraph()
                self.discovery_thread = hub.spawn(self._discover_topology)
                # Start traffic monitor thread.
                self.monitor_thread = hub.spawn(self._monitor_traffic)
                self.analyzer_thread = hub.spawn(self._analyze_traffic)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.edges:
                print("Edge node dpid= {0} disconnected".format(datapath.id))
            else:
                print("Core node dpid= {0} disconnected".format(datapath.id))
            del self.datapaths[datapath.id]
            del self.dp_stats[datapath.id]
            del self.dp_overload_ports[datapath.id]
            del self.dp_flows[datapath.id]
            del self.neglect_nodes[datapath.id]
            del self.dp_port_stats[datapath.id]
            del self.dp_port_stats_diff[datapath.id]
            try:
                self.network.remove_node(datapath.id)
            except nx.exception.NetworkXError:
                print ("ERROR: Node {0} was not in the network graph".format(datapath.id))
            self.connected_node_ct -= 1

    def _analyze_traffic(self):
        """
        Analyzes the flows in the datapaths and installs microflow rules 
        that divert parts of the flow through a different route.
        """
        hub.sleep(5)  # Skew this thread by 5 seconds, to that of monitor thread
        while True:
            hub.sleep(TRAFFIC_MONITOR_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY is False:  # When the network is stable
                for dp in self.datapaths.values():
                    self._install_microflow_rules(dp)

    def _install_microflow_rules(self, datapath):
        neg_nodes = self.neglect_nodes[datapath.id]
        micro_flows = list(self.dp_flows[datapath.id])
        # TODO: Reset the neglect_nodes and dp_flows
        print ("{0} Neglected Nodes: {1}".format(datapath.id, neg_nodes))
        print ("Micro Flow RUles: {0}".format(micro_flows))
        self.neglect_nodes[datapath.id] = set()
        self.dp_flows[datapath.id] = set()
        # micro_rules shall only have those micro-flows that were outgoing of the
        # overloaded ports.
        if neg_nodes and micro_flows:
            gr = self.network.copy()
            # Remove the neglected nodes from the network view of this datapath
            for node in neg_nodes:
                gr.remove_node(node)
            src = datapath.id
            # Route half of the flows through a new channel.
            for rule in micro_flows[:len(micro_flows)//2]:
                for edge, net in self.edges.items():  # For each rule pick the concerned edge
                    if edge == src:
                        continue
                    if net[0].address == rule.dst_ip:
                        try:
                            path = nx.dijkstra_path(gr, src, edge)
                            src_out_port = gr[src][path[1]]['src_port']
                            parser = datapath.ofproto_parser
                            #flow_ = namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")
                            if rule.proto == in_proto.IPPROTO_UDP:
                                match = parser.OFPMatch(eth_type=IP, ip_proto=rule.proto, ipv4_src=rule.src_ip,
                                                        ipv4_dst=rule.dst_ip, udp_src=rule.src_port, udp_dst=rule.dst_port)
                            elif rule.proto == in_proto.IPPROTO_TCP:
                                match = parser.OFPMatch(eth_type=IP, ip_proto=rule.proto, ipv4_src=rule.src_ip,
                                                        ipv4_dst=rule.dst_ip, tcp_src=rule.src_port, tcp_dst=rule.dst_port)
                            else:
                                print ("ERROR in microflow rule {0}".format(rule))
                                return
                            actions = [parser.OFPActionOutput(port=src_out_port)]
                            # TODO: Forgot timeout?
                            self._add_flow(datapath, priority=100, match=match,
                                           actions=actions)
                            print ("{0} Rule Added {1} action output: {2}".format(src, match, src_out_port))
                        except nx.exception.NetworkXNoPath:
                            print ("WARNING: No new path from {0} to {1}".format(src, edge))
                            continue

    def _monitor_traffic(self):
        """
        Get port data for each switch in the network.
        """
        while True:
            hub.sleep(TRAFFIC_MONITOR_INTERVAL)
            if self.REPEAT_TOPOLOGY_DISCOVERY is False:  # When the nework is stable
                for dp in self.datapaths.values():
                    # Request Port stats.
                    #pdb.set_trace()
                    self._request_port_stats(dp)

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        print ("Sent port stats request to {0}".format(datapath.id))
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        print ("\nDPID {0}".format(datapath.id), end="\t")
        for port_stat in body:
            port = port_stat.port_no
            if port >= OFPP_MAX:  # If a virtual port. then Ignore
                continue
            if datapath.id in self.edges and port == self.edges[datapath.id][0].port:
                # Don't consider ports connecting host nodes to edge nodes.
                continue
            self._save_port_stats(datapath.id, port_stat)
            weight = self._port_weight(datapath.id, port)
            # We overwrite past stats.
            self.dp_stats[datapath.id][port_stat.port_no] = weight
            #print("dpid = {0}, port_no={1}, weight={2}".format(datapath.id, port, self.dp_stats[datapath.id][port]))
        overloaded_ports = self._overloaded_ports(datapath.id)
        print("Overloaded ports: = {0}".format(overloaded_ports), end="\t")

        self.dp_overload_ports[datapath.id] = overloaded_ports

        for dst, ports in self.network.adj[datapath.id].items():
            if ports['src_port'] in overloaded_ports:
                self.neglect_nodes[datapath.id].add(dst)
        print ("Neglected nodes = {1}\n".format(datapath.id, self.neglect_nodes[datapath.id]))
        # Request flow stats for this datapath
        self._request_flow_stats(datapath)

    def _save_port_stats(self, dpid, ps):
        port_no = ps.port_no
        if port_no in self.dp_port_stats[dpid]:
            stat_ = self.dp_port_stats[dpid][port_no]
            rx = ps.rx_packets - stat_.rx
            tx = ps.tx_packets - stat_.tx
            rx_err = ps.rx_errors - stat_.rx_err
            tx_err = ps.tx_errors - stat_.tx_err
            self.dp_port_stats[dpid][port_no] = port_stats_(ps.rx_packets, ps.tx_packets,
                                                            ps.rx_errors, ps.tx_errors)
            self.dp_port_stats_diff[dpid][port_no] = port_stats_(rx, tx, rx_err, tx_err)
        else:
            # port_stats_ = namedtuple("port_stats", "rx, tx, rx_err, tx_err")
            self.dp_port_stats[dpid][port_no] = port_stats_(ps.rx_packets, ps.tx_packets,
                                                            ps.rx_errors,ps.tx_errors)
            self.dp_port_stats_diff[dpid][port_no] = port_stats_(0,0,0,0)
        # print("Port stats dpid {0} : {1}".format(dpid, self.dp_port_stats[dpid]))
        # print("Port stats dpid {0} : {1}".format(dpid, self.dp_port_stats_diff[dpid]))
        #pdb.set_trace()

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        #print ("Sending Flow stats request to dpid {0}".format(datapath.id))
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print ("Received flow stats reply from datapath {0}".format(datapath.id))
        for stat in body:
            # Clear flow stats from the datapath
            #print
            #self._clear_stats(datapath, match=stat.match, inst=stat.instructions)
            #print ("Match: {0}".format(stat.match))
            #print ("Instructions: {0}".format(stat.instructions))
            for ac in stat.instructions:
                send_to_controller = False
                for action in ac.actions:
                    if isinstance(action, OFPActionOutput):
                        # check if this flow stat is for one of the overloaded ports
                        if action.port in self.dp_overload_ports[datapath.id]:
                            match = stat.match
                            send_to_controller = True
                if send_to_controller is True:
                    ac.actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER))
                    # For analysis, we need data at the controller. This will cause extra disruptions.
                    # Would have been better if we could leave the controller out of this.
#                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
#                   inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=MAX_PRIORITY, match=match,
                                            flags=OFPFF_RESET_COUNTS, hard_timeout=HARD_TIMEOUT,
                                            instructions=stat.instructions)
                    datapath.send_msg(mod)
                    print ("\nDpid {0} match: {1} Send to CONTROLLER\n".format(datapath.id, match))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            # We only handle IP packets at the controller.
            #print ("{0}".format(eth.ethertype), end="\t")
            return
        datapath = msg.datapath
        ip = pkt.get_protocols(ipv4.ipv4)[0]
        #pdb.set_trace()
        # Only those IP packets will come to controller that were going out of the
        # the overloaded ports.
        #print ()
        if ip.proto == in_proto.IPPROTO_ICMP:  # ICMP
            icmp_packet = pkt.get_protocols(icmp.icmp)[0]
            # Don't modify paths for ICMP traffic. It causes a lot of churn.
            #print ("{0} Received ICMP packet {1}".format(datapath.id, icmp_packet))
        elif ip.proto == in_proto.IPPROTO_TCP:  # TCP
            tcp_ = pkt.get_protocols(tcp.tcp)[0]
            self.dp_flows[datapath.id].add(flow_(in_proto.IPPROTO_TCP, ip.src,
                                                 ip.dst, tcp_.src_port, tcp_.dst_port))
            # print ("{0} Received TCP packet src_ip={1}, dst_ip={2}, src_port={3}, dst_port={4}".format(
            #     datapath.id, ip.src, ip.dst, tcp_.src_port, tcp_.dst_port))
        elif ip.proto == in_proto.IPPROTO_UDP:  # UDP
            # namedtuple("flow", "proto, src_ip, dst_ip, src_port, dst_port")
            udp_ = pkt.get_protocols(udp.udp)[0]
            self.dp_flows[datapath.id].add(flow_(in_proto.IPPROTO_UDP, ip.src,
                                                 ip.dst, udp_.src_port, udp_.dst_port))
            # print("{0} Received UDP packet src_ip={1}, dst_ip={2}, src_port={3}, dst_port={4}".format(
            #     datapath.id, ip.src, ip.dst, udp_.src_port, udp_.dst_port))
        #print("{0} : Flow stats = {1}".format(datapath.id, self.dp_flows[datapath.id]))

    # def _clear_stats(self, datapath, match, inst):
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_MODIFY,
    #                             flags=OFPFF_RESET_COUNTS,
    #                             match=match, instructions=inst)
    #     datapath.send_msg(mod)
    #     print ("dpid {0} Cleared stats ".format(datapath.id))

    def _average_weight(self, port_weight):
        try:
            wts = [wt for pt, wt in port_weight.items() if wt != 0 and pt < OFPP_MAX]
            avg = sum(wts)/len(wts)
            print ("Weight = {0}, average={1}".format(wts, avg), end="\t")
            return avg
        except ZeroDivisionError:
            # retun zero the stats received was empty
            # print ("ZeroDivision ERROR")
            return 0

    def _overloaded_ports(self, dpid):
        avg_wt = self._average_weight(self.dp_stats[dpid])
        ov = [port for port, weight in self.dp_stats[dpid].items() if weight > (OVERLOAD_FACTOR+1) * avg_wt]
        return ov

    def _port_weight(self, dpid, port_no):
        return self.dp_port_stats_diff[dpid][port_no].tx

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
                # Start discover
                self._discover_()
                # Run Dijkstra. Find the shortest path from each datapath to each edge
                self._dijkstra_shortest_path()
                self._install_proactive_flows()
                self.REPEAT_TOPOLOGY_DISCOVERY = False

    def _dijkstra_shortest_path(self):
        print ("Inside Dijkstra")
        print (self.__str__())
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
                self.network.add_edge(link.src.dpid, link.dst.dpid, WEIGHT=1, src_port=link.src.port_no,
                                      dst_port=link.dst.port_no)
            else:
                print ("WARNING: link.src={0} and link.dst={1} not in self.datapaths. SKIPPED".format(
                    link.src.dpid, link.dst.dpid))

    def _add_arp_broadcast_rule(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(datapath, priority=1, match=match, actions=actions)

    def _add_flow(self, datapath, priority, match, actions, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                flags=OFPFF_RESET_COUNTS, instructions=inst,
                                idle_timeout=timeout, hard_timeout=timeout)
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
            x, self.network[x][y]['src_port'], y, self.network[x][y]['dst_port']) for x, y in self.network.edges()])
        return ret_str
