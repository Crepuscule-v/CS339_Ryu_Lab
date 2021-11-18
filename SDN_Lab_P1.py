#!/usr/bin/python3.8
# 2021.11.14 crepuscule77
 
from logging import Logger
from os import link
from eventlet.greenthread import sleep
from networkx.algorithms.planarity import ConflictPair
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, arp, ether_types, packet, ipv4
import ryu_get_network_topo
from ryu.lib import hub

class path_switches (app_manager.RyuApp):
    """
    SDN Lab Problem 1
    """
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "networkTopoGet" : ryu_get_network_topo.networkTopoGet
    }
    
    def __init__(self, *_args, **_kwargs):
        super().__init__(*_args, **_kwargs)
        self.getNetworkTopo = _kwargs["networkTopoGet"]
        self.path = []                  # [(dpid, in_port, out_port)]
        self.pathForCompare = []        # [(dpid, in_port)]
        self.datapaths = {}             # {dpid : datapath}
        self.priority = 1
        self.INTERVAL = 5
        # self.draw = hub.spawn(self.draw_topo())

    def add_flow(self, _datapath, _priority, _match, _actions, _idle_time=0, _hard_time=0):
        """
        Add flow entry to a specific switch
        """
        ofp_proto = _datapath.ofproto
        ofp_parser = _datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofp_proto.OFPIT_APPLY_ACTIONS, _actions)]

        flow_mod = ofp_parser.OFPFlowMod(_datapath, priority=_priority, match=_match, idle_timeout=_idle_time, hard_timeout=_hard_time, instructions=inst)
        _datapath.send_msg(flow_mod)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        data = msg.data
        in_port = msg.match["in_port"]

        pkt = packet.Packet(data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_arp = pkt.get_protocol(arp.arp)

        # Ignore LLDP and arp packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or pkt_arp:
            return

        if pkt_ipv4:
        # set net flow kkkimjtables for all switches
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            self.set_new_flow_tables(src_ip, dst_ip)

    def draw_topo(self, path):
        self.getNetworkTopo.get_topo_real_time(path)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, event):
        """
        Record datapath to self.datapaths {}
        """
        datapath = event.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath


    def get_new_path(self, src_ip, dst_ip):
        # {(src_dpid, port) : {dst_dpid, port}}
        linksBetweenSwitch = self.getNetworkTopo.linksBetweenSwitch
        # {host_ip : [(src_dpid, port)]}
        hostToSwitch = self.getNetworkTopo.hostToSwitch
        # {host_ip -> mac}
        hosts = self.getNetworkTopo.hosts  
        # {dpid -> [ports]}
        portsOfSwitch = self.getNetworkTopo.portsOfSwitch
        # {(src_dpid, port) : host_ip}
        linksToHost = self.getNetworkTopo.linksToHost

        print("link_to_host: ", linksToHost)

        if not hostToSwitch.__contains__(src_ip):
            sleep(3)
            return False

        # DFS
        first_hop = hostToSwitch[src_ip]
        stack = []
        stack.append(first_hop)
        children_node = {}              # {dpid, []}
        new_path = []                   # record the path
        visited = {}                    # {dpid : bool}

        while (len(stack)):
            temp_node = stack[-1]       # (dpid, in_port)
            if not children_node.__contains__(temp_node[0]):
                children_node[temp_node[0]] = []
            visited[temp_node[0]] = True
            if temp_node[0] == dst_ip:  
                if self.pathForCompare != stack:
                    break

            Flag = False
            if temp_node[0] != dst_ip:
                for out_port in portsOfSwitch[temp_node[0]]:
                    if out_port == temp_node[1]:
                        continue
                    if linksBetweenSwitch.__contains__((temp_node[0], out_port)):
                        next_hop = linksBetweenSwitch[(temp_node[0], out_port)]
                    elif linksToHost.__contains__((temp_node[0], out_port)):
                        next_hop = (linksToHost[(temp_node[0], out_port)], 0)
                    if not visited. __contains__(next_hop[0]) or visited[next_hop[0]] == False:
                        stack.append(next_hop)
                        children_node[temp_node[0]].append(next_hop[0])
                        Flag = True
                        break

            if not Flag:
                stack.pop(-1)
                for switch in children_node[temp_node[0]]:
                    visited[switch] = False
            sleep(0.5)
        
        if len(stack) == 0:
            print("No Usable Path")
            return False

        self.pathForCompare.clear()
        for i in range(0, len(stack) - 1):
            dpid = stack[i][0]
            in_port = stack[i][1]
            next_hop= stack[i + 1]
            for port in portsOfSwitch[dpid]:
                if (linksBetweenSwitch.__contains__((dpid, port)) and linksBetweenSwitch[(dpid, port)] == next_hop) or (linksToHost.__contains__((dpid, port)) and linksToHost[(dpid, port)] == next_hop[0]):
                    out_port = port
                    break
            new_path.append((dpid, in_port, out_port))
            self.pathForCompare.append((dpid, in_port))
        
        self.pathForCompare.append((dst_ip, 0))
        self.path = new_path
        print(src_ip, " ->  " , self.path)
        return True

    
    # TODO : Bothway !  <-> 
    def set_new_flow_tables(self, src_ip, dst_ip):
        while not self.get_new_path(src_ip, dst_ip):
            self.get_new_path(src_ip, dst_ip)

        priority = self.priority + 1
        for node in self.path:
            dpid = node[0]
            in_port = node[1]
            out_port = node[2]
            datapath = self.datapaths[dpid]
            ofp_parser = datapath.ofproto_parser
            # A -> B
            actions_1 = [ofp_parser.OFPActionOutput(out_port)]
            match_1 = ofp_parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            self.add_flow(datapath, _priority=priority, _match=match_1, _actions=actions_1, _hard_time=self.INTERVAL)

            # B -> A
            actions_2 = [ofp_parser.OFPActionOutput(in_port)]
            match_2 = ofp_parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
            self.add_flow(datapath, _priority=priority, _match=match_2, _actions=actions_2, _hard_time=self.INTERVAL)

        self.priority = priority
        path_for_draw = [(src_ip, 0, 0)] + self.path + [(dst_ip, 0, 0)]
        self.draw_topo(path_for_draw)
