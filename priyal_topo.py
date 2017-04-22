#################### Code to discover network topology #####################################
# 1. creating a graph that consists of switches as nodes and links between switches as edges
# 2. create a link table switch_link_table that consists of (src_dpid, dst_dpid)->(src_port, dst_port)
# 3. create a dictionary that contains detail of all  ports available to all switches, i.e. switch_port_table(dpid->[port_num])
# 4. There will be two types of ports in a switch, ports that connect with other switch switch_switch_port and ports that are connected with host switch_host_port
# 5.
# Author: Priyal Jain
# GitHub : https://github.com/Jainpriyal/ryu/tree/master/ryu/app/qos_routing
############################################################################################
import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu import cfg
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
import constants


class DiscoverTopology(app_manager.RyuApp):
    """
        Class to discover topology
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DiscoverTopology, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "topologydiscovery"
        self.switch_link_table = {}  # {(src.dpid, dst.dpid):(src.port_no, dst.port_no)}
        self.switch_host_access_table = {}  # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # {sw:set(all available ports)}
        self.switch_host_ports = {}  # {sw:set(ports connected with host)}
        self.switch_to_switch_ports = {}  # {sw: set(ports connected with other switch)}

        self.database = nx.DiGraph()
        self.pre_database = nx.DiGraph()
        self.pre_switch_host_access_table = {}
        self.pre_switch_link_table = {}
        self.shortest_paths = None

        # Start a green thread to discover network resource.
        self.discover_thread = hub.spawn(self._discover)

    def _discover(self):
        """
	     main function that gets triggered by init
             it will run continously 
             and invokes get_topology and display_topology function within every topology_discovery_time
        """
        i = 0
        while True:
            self.display_topology()
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(constants.TOPOLOGY_DISCOVERY_PERIOD)
            i = i + 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            When switches are connecting with controller they send feature information
	    For new switches connecting to controller, install miss-table flow entry to datapaths
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected.......", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def retrieve_dpid_connected_host(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
	    return the dpid of the switch where host is connected
	    switch host access table contains (dpid, port)->(host_ip, host_mac_addr) 
        """
        for key in self.switch_host_access_table.keys():
            if self.switch_host_access_table[key][0] == host_ip:
                self.logger.info("location of %s is found %s" % (host_ip, key))
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.switch_link_table

    def create_switch_adjacency_matrix(self, link_list):
        """
            Form switch Adjacency Matrix
	    It will display what all switches are connected with what all other switches 
        """
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.database.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.database.add_edge(src, dst, weight=1)
        return self.database

    ## In every switch there are two types of ports:
    ## a] ports connected to other switches
    ## b] ports connected to other hosts
    def create_switch_port_table(self, switch_list):
        """
           create table containing switch and all its ports 
           it will contain total ports, ports connected to switch and ports connected to hosts(both)
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.switch_to_switch_ports.setdefault(dpid, set())
            self.switch_host_ports.setdefault(dpid, set())
            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_switch_to_switch_links(self, link_list):
        """
            create link table: containing source and destination port
            switch_link_table: (src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            ## creating links between switches
            self.switch_link_table[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            if link.src.dpid in self.switches:
                self.switch_to_switch_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.switch_to_switch_ports[link.dst.dpid].add(link.dst.port_no)

    def create_switch_to_host_links(self):
        """
            Get ports without link into switch_host_ports
	    these ports are either connected with hosts or not connected
        """
        for sw in self.switch_port_table:
            all_port = self.switch_port_table[sw]
            interior_port = self.switch_to_switch_ports[sw]
            self.switch_host_ports[sw] = all_port - interior_port

    # List the event list should be listened.
    @set_ev_cls([event.EventSwitchEnter,
                 event.EventSwitchLeave, event.EventPortAdd,
                 event.EventPortDelete, event.EventPortModify,
                 event.EventLinkAdd, event.EventLinkDelete])
    def get_topology(self, ev):
        """
          Fetch all the details about network topology 
        """
        switch_list = get_switch(self.topology_api_app, None)
        self.create_switch_port_table(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_switch_to_switch_links(links)
        self.create_switch_to_host_links()
        self.create_switch_adjacency_matrix(self.switch_link_table.keys())

    def create_switch_host_access_table(self, dpid, in_port, ip, mac):
        """
            Register informtion about which host is connected with which switch 
	    It will update a dictinary containing (switch id and switch port) --> ip address and mac address of host
        """
        if in_port in self.switch_host_ports[dpid]:
            if (dpid, in_port) in self.switch_host_access_table:
                if self.switch_host_access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.switch_host_access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.switch_host_access_table.setdefault((dpid, in_port), None)
                self.switch_host_access_table[(dpid, in_port)] = (ip, mac)
                return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac

            # Record the access info
            self.create_switch_host_access_table(datapath.id, in_port, arp_src_ip, mac)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
         This function will display status of port   
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("\nPort {} added in switch {}".format(port_no, dpid))
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("\nPort {} delete in switch {}".format(port_no, dpid))
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("\nPort {} modified in switch {}".format(port_no, dpid))
        else:
            self.logger.info("\nStatus of Port {} in switch {} is unknown".format(port_no, dpid))

    def display_topology(self):
        """
            it will display topology when ever there is any change
	"""

        switch_num = len(self.database.nodes())
        if set(self.pre_database) != set(self.database) and constants.SHOWTOPOLOGY:
            print "--------------------- Switch Adjacency Matrix ---------------------"
            print '%10s' % ("switch"),
            for i in self.database.nodes():
                print '%10d' % i,
            print ""
            for i in self.database.nodes():
                print '%10d' % i,
                for j in self.database[i].values():
                    print '%10.0f' % j['weight'],
                print ""
            self.pre_database = copy.deepcopy(self.database)
        if self.pre_switch_link_table != self.switch_link_table and constants.SHOWTOPOLOGY:
            print "--------------------- Switch Link Matrix ---------------------"
            print '%10s' % ("switch"),
            for i in self.database.nodes():
                print '%10d' % i,
            print ""
            for i in self.database.nodes():
                print '%10d' % i,
                for j in self.database.nodes():
                    if (i, j) in self.switch_link_table.keys():
                        print '%10s' % str(self.switch_link_table[(i, j)]),
                    else:
                        print '%10s' % "No-link",
                print ""
            self.pre_switch_link_table = copy.deepcopy(self.switch_link_table)
        if self.pre_switch_host_access_table != self.switch_host_access_table and constants.SHOWTOPOLOGY:
            print "----------------Access Host-------------------"
            print '%10s' % ("switch"), '%12s' % "Host"
            if not self.switch_host_access_table.keys():
                print "    NO found host"
            else:
                for tup in self.switch_host_access_table:
                    print '%10d:    ' % tup[0], self.switch_host_access_table[tup]
            self.pre_switch_host_access_table = copy.deepcopy(self.switch_host_access_table)
