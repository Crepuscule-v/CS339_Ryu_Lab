#!/usr/bin/python3.8
# 2021.11.14 crepuscule77

import logging
import sys

sys.path.append("../../") 
sys.path.append("/usr/local/lib/python3.8/dist-packages")

from struct import pack
from eventlet.wsgi import DEFAULT_MAX_HTTP_VERSION
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ipv4, arp, ethernet, ether_types, packet
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import matplotlib.pyplot as plt

switch_modify_event_list = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

class networkTopoGet(app_manager.RyuApp):
    """
    Get network topology
    """
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super().__init__(*_args, **_kwargs)
        self.portsOfSwitch = {}             # {dpid -> [ports]}
        self.allSwitches = set()            # (dpid)
        self.onlineSwitches = set()         # (dpid)
        self.linksBetweenSwitch = {}        # {(src_dpid, port) : {dst_dpid, port}}
        self.linksToHost = {}               # {(src_dpid, port) : host_ip}
        self.hostToSwitch = {}              # {host_ip : [(src_dpid, port)]}
        self.hosts = {}                     # {host_ip -> mac}
        self.multicast_record = {}          # {(dpid, src_ip, dst_ip) : in_port}
        self.mac_to_port = {}               # {dpid : {mac : port}}
        self.graph = nx.Graph()
        self.logger = logging.getLogger("NetWorkTopoLogger")
        # self.update_topo = hub.spawn(self.get_topo_real_time)

    def get_topo_real_time(self, path=[]):
        self.regetNetTopo(None)
        hub.sleep(2)
        self.draw_topo(path)
        hub.sleep(3)

    def add_flow(self, _datapath, _priority, _match, _actions, _idle_timeout=0, _hard_timeout=0):
        """
        Add flow entry to a specific switch
        """
        ofp_proto = _datapath.ofproto
        ofp_parser = _datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofp_proto.OFPIT_APPLY_ACTIONS, _actions)]
        flow_mod = ofp_parser.OFPFlowMod(_datapath, priority=_priority, match=_match, idle_timeout=_idle_timeout, hard_timeout=_hard_timeout, instructions=inst)
        _datapath.send_msg(flow_mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, event):
        """
        Set table-miss flow entry
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if not isinstance(datapath.id, type(None)):
            self.logger.info("Switch %d Has Connected" %datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    def host_register(self, ip, mac, datapath, port):
        self.hosts[ip] = mac
        if ip in self.linksToHost.values():
            return 
        self.linksToHost.setdefault((datapath.id, port), ip)
        self.hostToSwitch.setdefault(ip, (datapath.id, port))
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """
        Find hosts by capture arp packets
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = msg.data
        in_port = msg.match["in_port"]

        pkt = packet.Packet(data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        arp_packet = pkt.get_protocol(arp.arp)
        # We simply handle the arp packet in this app
        if arp_packet:
            self.handle_arp_packet(msg)

    def handle_arp_packet(self, msg):
        datapath = msg.datapath
        arp_packet = packet.Packet(msg.data).get_protocol(arp.arp)
        in_port = msg.match["in_port"]
        src_ip = arp_packet.src_ip
        dst_ip = arp_packet.dst_ip
        mac = arp_packet.src_mac

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Need to solve multi-regist and multi learning problem
        self.mac_learning(datapath.id, mac, in_port)
        self.host_register(src_ip, mac, datapath, in_port)
        self.flood(msg, datapath, in_port, arp_packet)
    
    def mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid].setdefault(src_mac, in_port)
        

    def flood(self, msg, datapath, in_port, arp_packet):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        dpid = datapath.id
        
        # We need to solve the arp stroms 
        # Make sure that for a specific multicast packet
        # There is only one in_port for it for every switch

        if self.multicast_record. __contains__((dpid, arp_packet.src_ip, arp_packet.dst_ip)):
            if self.multicast_record[(dpid, arp_packet.src_ip, arp_packet.dst_ip)] != in_port:
                # just drop it
                _msg = ofp_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[], data=None
                )
                datapath.send_msg(_msg)
                self.logger.info("Drop extra arp packet to avoid arp stroms")
                return 

        self.multicast_record[(dpid, arp_packet.src_ip, arp_packet.dst_ip)] = in_port
        for out_port in self.portsOfSwitch[dpid]:
            if out_port != in_port:
                actions = [ofp_parser.OFPActionOutput(out_port)]
                _msg = ofp_parser.OFPPacketOut(
                    datapath = datapath,
                    buffer_id = datapath.ofproto.OFP_NO_BUFFER,
                    in_port = in_port,
                    actions = actions,
                    data = msg.data
                )
                datapath.send_msg(_msg)
        return
                

    def constructor(self, switches, links):
        """
        Add switches, ports, links to self.allSwitches, self.protOfSwitch, self.linksBetweenSwitch
        """
        self.onlineSwitches = set()
        for switch in switches:
            dpid = switch.dp.id
            self.onlineSwitches.add(dpid)
            self.allSwitches.add(dpid)
            self.portsOfSwitch.setdefault(dpid, set())
            for port in switch.ports:
                self.portsOfSwitch[dpid].add(port.port_no)
        
    
        # Links should be cleared each time 
        self.linksBetweenSwitch.clear()
        for link in links:
            src_dp = link.src
            dst_dp = link.dst
            self.linksBetweenSwitch[(src_dp.dpid, src_dp.port_no)] = (dst_dp.dpid, dst_dp.port_no)

        # self.printinfo()
    

    @set_ev_cls(switch_modify_event_list, None)
    def regetNetTopo(self, event):
        """
        The handler must have a para 'event'
        """
        switches = get_switch(self, None)
        links = get_link(self, None)
        self.constructor(switches, links)
        self.get_network_topo_graph()
        return

    
    def get_network_topo_graph(self):
        new_graph = nx.Graph()

        # draw nodes
        for switch in self.onlineSwitches:
            node = "switch_" + str(switch)
            new_graph.add_node(node, type="switch")

        for host in self.hosts.keys():
            node = "host_" + str(host)
            new_graph.add_node(node, type="host")

        # draw edges
        for src, dst in self.linksBetweenSwitch.items():
            # {(src_dpid, port) <-> {dst_dpid, port}}
            node_1 = "switch_" + str(src[0])
            node_2 = "switch_" + str(dst[0])
            new_graph.add_edge(node_1, node_2, type="ss", weight=5, minlen=20)

        for switch, host in self.linksToHost.items():
            node_1 = "switch_" + str(switch[0])
            node_2 = "host_" + str(host)
            new_graph.add_edge(node_1, node_2, type="hs", weight=5, minlen=20)

        self.graph = new_graph

    def draw_topo(self, path=[]):
        node_color_list = []
        edge_color_list = []
        _node_type = nx.get_node_attributes(self.graph, 'type')
        _edge_type = nx.get_edge_attributes(self.graph, 'type')
        for node in self.graph.nodes:
            if _node_type[node] == "switch":
                node_color_list.append("black")
            else:
                node_color_list.append("blue")

        # Try the fix the pos of the host node to improve visibility
        host_pos = []
        special_pos = {}
        _path_txt = "PATH: \n"
        end_node =  ""

        for i in range(0, len(path) - 1):
            node_1 = "switch_" + str(path[i][0])
            node_2 = "switch_" + str(path[i + 1][0])
            if i == 0:
                node_1 = "host_" + str(path[i][0])
                host_pos.append(node_1)
                special_pos[node_1] = (0, 2)
            if i == len(path) - 2:
                node_2 = "host_" + str(path[i + 1][0])
                host_pos.append(node_2)
                special_pos[node_2] = (6, 2)
            end_node = node_2
            _path_txt += str(node_1) + " -> "
            self.graph[node_1][node_2].update(type="path")
        _path_txt += end_node

        for edge in self.graph.edges:
            _type = self.graph.edges[edge]["type"]
            if _type == "ss" or _type == "hs":
                edge_color_list.append("black")
            elif _type == "path":
                edge_color_list.append("red")        
        
        pos = nx.spring_layout(self.graph, pos=special_pos, fixed=host_pos)
        args = {
            'pos':pos,
            'font_size':8,
            'alpha':0.4,
            'node_size':400,
            'width':1,
            'with_labels':True, 
            'edge_color':edge_color_list,
            'node_color':node_color_list,
        }
        plt.title(_path_txt)
        nx.draw(self.graph, **args)
        plt.show()


    def printinfo(self):
        print("\n")
        print ("all Switches: ", self.allSwitches)
        print ("online Switches: ", self.onlineSwitches)
        print ("linksBetweenSwitch: ", self.linksBetweenSwitch)
        print ("host_list", self.hosts)
        print ("linksToHost: ", self.linksToHost)
        print ("mac_learning_table: ", self.mac_to_port)
        print("\n")