from __future__ import print_function
import pdb

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


TOPOLOGY_DISCOVERY_INTERVAL=50

class BaseNetwork(app_manager.RyuApp):
    """
    The Network class which keeps network topology, datapath status,
    finds shortest path between Ingress and Egress nodes and collects 
    network statistics.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        """
        Initialize an empty dictionary to keep datapath objects.
        Start the network topology discovery routine to run at constant interval.
        Start the network traffic monitoring routine.
        """
        self.datapaths = {}
        self.discovery = hub.spawn(self._discover_topology)

    def _discover_topology(self):
        """
        This thread infinitely runs at a periodic interval 
        :return: 
        """
        while True:
            hub.sleep(TOPOLOGY_DISCOVERY_INTERVAL)
            self._discover()

    def _discover(self):
        nodes = get_switch(self)
        links = get_link(self)
        pdb.set_trace()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _datapath_state_change_handler(self, ev):
        """
        Add/Remove datapath objects to/from the datapath dictionary 
        Source: Adapted from Ryubook section 3.2
        """
        pdb.set_trace()
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            print ("Added dpid {0}".format(hex(datapath.id)))

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                print ("Removed dpid {0}".format(hex(datapath.id)))
