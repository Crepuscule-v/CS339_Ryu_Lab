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
    SDN Lab Problem 3
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
        
        if dpid == 1:
            weight = 0
            # port_2
            port_2 = 2
            actions_to_port_2 = [ofp_parser.OFPActionOutput(port_2)]

            # port_3
            port_3 = 3
            actions_to_port_3 = [ofp_parser.OFPActionOutput(port_3)]

            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight, port_2, watch_group, actions_to_port_2),
                ofp_parser.OFPBucket(weight, port_3, watch_group, actions_to_port_3)
            ]
            # fast failover
            _group_id = 77
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_FF, _group_id, buckets)
            datapath.send_msg(msg)
            sleep(1)

            actions = [ofp_parser.OFPActionGroup(group_id=77)]
            match = ofp_parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1")
            self.add_flow(datapath, 10, match, actions)

            # #add the return flow for h1 in s1.
            actions = [ofp_parser.OFPActionOutput(1)]
            match = ofp_parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)

            actions = [ofp_parser.OFPActionOutput(1)]
            match = ofp_parser.OFPMatch(in_port=3)
            self.add_flow(datapath, 10, match, actions)


        elif dpid == 2:
            port_1 = 1
            port_2 = 2
            port_3 = 3
            weight = 0

            actions_to_port_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_to_port_2 = [ofp_parser.OFPActionOutput(port_2)]

            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight, port_1, watch_group, actions_to_port_1),
                ofp_parser.OFPBucket(weight, port_2, watch_group, actions_to_port_2)
            ]
            # fast failover
            _group_id = 77
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_FF, _group_id, buckets)
            datapath.send_msg(msg)
            sleep(1)

            actions = [ofp_parser.OFPActionGroup(group_id=77)]
            match = ofp_parser.OFPMatch(in_port=port_3, eth_type=0x0800, ipv4_src="10.0.0.2", ipv4_dst="10.0.0.1")
            self.add_flow(datapath, 10, match, actions)

            # normal condition
            actions = [ofp_parser.OFPActionOutput(port_3)]
            match = ofp_parser.OFPMatch(in_port=port_1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2")
            self.add_flow(datapath, 10, match, actions)
            
            actions = [ofp_parser.OFPActionOutput(port_3)]
            match = ofp_parser.OFPMatch(in_port=port_2, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2")
            self.add_flow(datapath, 10, match, actions)
            
            # we need to deal with the emergencies
            # such as there is a break in the middle of the link
            actions = [ofp_parser.OFPActionOutput(port_2)]
            match = ofp_parser.OFPMatch(in_port=port_1, eth_type=0x0800, ipv4_src="10.0.0.2", ipv4_dst="10.0.0.1")
            self.add_flow(datapath, 10, match, actions)

            actions = [ofp_parser.OFPActionOutput(port_1)]
            match = ofp_parser.OFPMatch(in_port=port_2, eth_type=0x0800, ipv4_src="10.0.0.2", ipv4_dst="10.0.0.1")
            self.add_flow(datapath, 10, match, actions)
        
        elif dpid == 3 or dpid == 4:
            # If we want to send the packet to the input port
            # we must use ofproto_v1_3.OFPP_IN_PORT to represent the in_put port

            port_1 = 1
            port_2 = 2
            weight = 0
            
            actions_to_port_1_BACK = [ofp_parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]
            actions_to_port_2 = [ofp_parser.OFPActionOutput(port_2)]

            actions_to_port_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_to_port_2_BACK = [ofp_parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]

            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets_for_port_1 = [
                ofp_parser.OFPBucket(weight, port_2, watch_group, actions_to_port_2),       # out to port_2
                ofp_parser.OFPBucket(weight, port_1, watch_group, actions_to_port_1_BACK)        # out to port_1
            ]

            buckets_for_port_2 = [
                ofp_parser.OFPBucket(weight, port_1, watch_group, actions_to_port_1),       # out to port_1
                ofp_parser.OFPBucket(weight, port_2, watch_group, actions_to_port_2_BACK)        # out to port_2
            ]

            # fast failover for port_1
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_FF, 1, buckets_for_port_1)
            datapath.send_msg(msg)
            sleep(1)

            actions = [ofp_parser.OFPActionGroup(group_id=1)]
            match = ofp_parser.OFPMatch(in_port=1, eth_type=0x0800)
            self.add_flow(datapath, 10, match, actions)

            # fast failover for port_2
            msg = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_FF, 2, buckets_for_port_2)
            datapath.send_msg(msg)
            sleep(1)

            actions = [ofp_parser.OFPActionGroup(group_id=2)]
            match = ofp_parser.OFPMatch(in_port=2, eth_type=0x0800)
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
        # Or it will affect the flow mod action

        # Remember to disable arp processing in get_network_topo.py  
        if ipv4_packet:
            while not self.getNetworkTopo.mac_to_port.__contains__(dpid):
                sleep(1)
            
            while not self.getNetworkTopo.mac_to_port[dpid].__contains__(dst_mac):
                sleep(1)
            
            out_port = self.getNetworkTopo.mac_to_port[dpid][dst_mac]
            actions = [ofp_parser.OFPActionOutput(out_port)]
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 10, match, actions)
            return 


    # These two functions are copied from RYU Official Document for debugging
    # We can simply ignore it
    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                            ofp.OFPTT_ALL,
                                            ofp.OFPP_ANY, ofp.OFPG_ANY,
                                            cookie, cookie_mask,
                                            match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                        'duration_sec=%d duration_nsec=%d '
                        'priority=%d '
                        'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                        'cookie=%d packet_count=%d byte_count=%d '
                        'match=%s instructions=%s' %
                        (stat.table_id,
                        stat.duration_sec, stat.duration_nsec,
                        stat.priority,
                        stat.idle_timeout, stat.hard_timeout, stat.flags,
                        stat.cookie, stat.packet_count, stat.byte_count,
                        stat.match, stat.instructions))
        print('FlowStats: %s', flows)

