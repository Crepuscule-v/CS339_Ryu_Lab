#!/usr/bin/python3.8
# -*- coding: utf8 -*-
 
import sys
from typing import Protocol
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
    
OF_PROTOCOL = 'OpenFlow13'

def NetWorkTopo():
    net = Mininet()
 
    info("Create host nodes.\n")
    h1 = net.addHost("h1")
    h2 = net.addHost("h2")
 
    info("Create switch node.\n")

    s1 = net.addSwitch("switch_1", dpid='1', switch=OVSSwitch, protocols=OF_PROTOCOL, failMode="secure")
    s2 = net.addSwitch("switch_2", dpid='2', switch=OVSSwitch, protocols=OF_PROTOCOL, failMode="secure")
    s3 = net.addSwitch("switch_3", dpid='3', switch=OVSSwitch, protocols=OF_PROTOCOL, failMode="secure")
    s4 = net.addSwitch("switch_4", dpid='4', switch=OVSSwitch, protocols=OF_PROTOCOL, failMode="secure")

    info("Connect to controller node.\n")
    net.addController(name='ryu_c1',controller=RemoteController,ip='127.0.0.1',port=6653)
 
    info("Create Links.\n")
    net.addLink(h1, s1)
    net.addLink(s1, s3)
    net.addLink(s1, s4)
    net.addLink(s2, s3)
    net.addLink(s2, s4)
    net.addLink(s2, h2)
 
    info("build and start.\n")
    net.build()
    net.start()
    CLI(net)
 
if __name__ == '__main__':
    setLogLevel('info')
    NetWorkTopo()
