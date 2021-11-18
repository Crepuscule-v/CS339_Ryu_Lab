#!/usr/bin/python3.8
 
from eventlet.greenthread import sleep
from networkx.classes.function import set_edge_attributes
from ryu.base import app_manager
from os import link
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, arp, ether_types, packet, ipv4
import ryu_get_network_topo

class load_balance (app_manager.RyuApp):
    """
    SDN Lab Problem 2
    """
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "networkTopoGet" : ryu_get_network_topo.networkTopoGet,
    }

    def __init__(self, *_args, **_kwargs):
        super().__init__(*_args, **_kwargs)
        self.getNetworkTopo = _kwargs["networkTopoGet"]
        

    def add_flow(self, _datapath, _priority, _match, _actions, _idle_time=0, _hard_time=0):
        """
        Add flow entry to a specific switch
        """
        ofp_proto = _datapath.ofproto
        ofp_parser = _datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofp_proto.OFPIT_APPLY_ACTIONS, _actions)]
        flow_mod = ofp_parser.OFPFlowMod(_datapath, priority=_priority, match=_match, idle_timeout=_idle_time, hard_timeout=_hard_time, instructions=inst)
        _datapath.send_msg(flow_mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler (self, event):
        """
        set group table for switch_1 and switch_2
        """
        datapath = event.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # Set group table for switch_1
        # 30% packets sent to port_2, 70% to port_3
        if dpid == 1:
            # port_2
            port_2 = 2
            weight_for_port_2 = 50
            actions_to_port_2 = [ofp_parser.OFPActionOutput(port_2)]

            # port_3
            port_3 = 3
            weight_for_port_3 = 50
            actions_to_port_3 = [ofp_parser.OFPActionOutput(port_3)]

            # Will not be used in select group
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight_for_port_2, watch_port, watch_group, actions_to_port_2),
                ofp_parser.OFPBucket(weight_for_port_3, watch_port, watch_group, actions_to_port_3)
            ]

            _group_id = 77
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, _group_id, buckets)
            datapath.send_msg(msg)

            # add flow entry make group_table apply to packets from host_1
            actions = [ofp_parser.OFPActionGroup(group_id=77)]
            match = ofp_parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2")
            self.add_flow(datapath, 10, match, actions)

            # #add the return flow for h1 in s1.
            # h1 is connected to port 3.
            actions = [ofp_parser.OFPActionOutput(1)]
            match = ofp_parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)

            actions = [ofp_parser.OFPActionOutput(1)]
            match = ofp_parser.OFPMatch(in_port=3)
            self.add_flow(datapath, 10, match, actions)
        elif dpid == 2:
            port_1 = 1
            weight_for_port_1 = 50
            actions_to_port_1 = [ofp_parser.OFPActionOutput(port_1)]

            port_2 = 2
            weight_for_port_2 = 50
            actions_to_port_2 = [ofp_parser.OFPActionOutput(port_2)]

            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight_for_port_1, watch_port, watch_group, actions_to_port_1),
                ofp_parser.OFPBucket(weight_for_port_2, watch_port, watch_group, actions_to_port_2)
            ]

            _group_id = 77
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, _group_id, buckets)
            datapath.send_msg(msg)
            sleep(1)

            # add flow entry make group_table apply to packets from host_2
            actions = [ofp_parser.OFPActionGroup(group_id=77)]
            match = ofp_parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="10.0.0.2", ipv4_dst="10.0.0.1")
            self.add_flow(datapath, 10, match, actions)

            actions = [ofp_parser.OFPActionOutput(3)]
            match = ofp_parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)

            actions = [ofp_parser.OFPActionOutput(3)]
            match = ofp_parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)

        elif dpid == 4 or dpid == 3:
            port_1 = 1 
            port_2 = 2
            # A -> B
            actions = [ofp_parser.OFPActionOutput(port_1)]
            match = ofp_parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)

            # B -> A
            actions = [ofp_parser.OFPActionOutput(port_2)]
            match = ofp_parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        data = msg.data
        in_port = msg.match["in_port"]
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_packet = pkt.get_protocol(arp.arp)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        dst_mac =  eth.dst
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or arp_packet:
            return 
        # We should ignore the ipv_6 pakcets
        # Or it will affect our normal flow

        if ipv4_packet:
            # waiting for mac learning 
            while not self.getNetworkTopo.mac_to_port.__contains__(dpid):
                sleep(1)
            
            while not self.getNetworkTopo.mac_to_port[dpid].__contains__(dst_mac):
                sleep(1)
            
            out_port = self.getNetworkTopo.mac_to_port[dpid][dst_mac]
            actions = [ofp_parser.OFPActionOutput(out_port)]
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 10, match, actions)
            return 
