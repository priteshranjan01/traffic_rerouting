from __future__ import print_function

import pdb

from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, DEAD_DISPATCHER

from base_network import BaseNetwork
from constants import *

from ryu.lib import hub


class MplsNetwork(BaseNetwork):
    """
    Creates an MPLS network. 
    Expects the Base Network to discover and monitor topology. 
    At startup creates an LSP across the shortest path between ingress and egress routes. 
    Analyses the network state and updates the LSPs as needed.
    """
    def __init__(self, *args, **kwargs):
        super(MplsNetwork, self).__init__(*args, **kwargs)
        self.ct = 1

    def _create_proactive_lsp(self):
        pass
