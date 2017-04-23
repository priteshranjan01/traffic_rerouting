from __future__ import print_function

from base_network import BaseNetwork
from constants import *

from ryu.lib import hub


class MplsNetwork(BaseNetwork):
    """
    Creates an MPLS network. At startup creates an LSP across the shortest 
    path between ingress and egress routes. 
    Analyses the network state and updates the LSPs as needed.
    """
    def __init__(self, *args, **kwargs):
        super(MplsNetwork, self).__init__(*args, **kwargs)
        self.ct = 1
        #self.network_stable = False
        self.discovery = hub.spawn(self._discover_topology)

    def _discover_topology(self, interval=TOPOLOGY_DISCOVERY_INTERVAL):
        """
        This thread infinitely runs at a periodic interval 
        """
        while True:
            hub.sleep(interval)
            self._discover_()
            self._dijkstra_shortest_path()
            self.ct += 1

    def _create_proactive_lsp(self):
        pass
