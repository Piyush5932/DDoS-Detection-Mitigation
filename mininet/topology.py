#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import sys
import os

def create_topology():
    """
    Create a network topology for DDoS attack simulation
    """
    # Create an empty network with a remote controller
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('*** Adding controller\n')
    # Change the IP address to match your Ryu controller
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    
    info('*** Adding hosts\n')
    # Normal hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    
    # Server hosts
    server1 = net.addHost('server1', ip='10.0.0.101/24')
    server2 = net.addHost('server2', ip='10.0.0.102/24')
    
    info('*** Creating links\n')
    # Connect hosts to switches
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s2, bw=10)
    net.addLink(h4, s2, bw=10)
    
    # Connect servers to switch 3
    net.addLink(server1, s3, bw=100)
    net.addLink(server2, s3, bw=100)
    
    # Connect switches
    net.addLink(s1, s3, bw=100)
    net.addLink(s2, s3, bw=100)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    
    info('*** Setting up server applications\n')
    # Start a simple HTTP server on server1
    server1.cmd('python3 -m http.server 80 &')
    
    # Start a simple echo server on server2
    server2.cmd('python3 -c "import socket; s=socket.socket(); s.bind((\'\', 8888)); s.listen(1); conn, addr = s.accept(); conn.send(conn.recv(1024))" &')
    
    info('*** Network is ready\n')
    
    return net

def simulate_normal_traffic(net):
    """
    Simulate normal network traffic
    """
    info('*** Simulating normal traffic\n')
    h1 = net.get('h1')
    h2 = net.get('h2')
    server1 = net.get('server1')
    server2 = net.get('server2')
    
    # HTTP requests
    h1.cmd('wget -q -O- http://10.0.0.101:80 &')
    h2.cmd('wget -q -O- http://10.0.0.101:80 &')
    
    # Ping traffic
    h1.cmd('ping -c 5 10.0.0.102 &')
    h2.cmd('ping -c 5 10.0.0.102 &')
    
    info('*** Normal traffic simulation started\n')

def print_attack_commands():
    """
    Print available attack commands for the user
    """
    info('\n*** Available DDoS Attack Commands ***\n')
    info('1. ICMP Flood: h1 hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood server1\n')
    info('2. SYN Flood: h1 hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood server1\n')
    info('3. UDP Flood: h1 hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood server1\n')
    info('\nUse these commands in the Mininet CLI to simulate attacks\n')

if __name__ == '__main__':
    setLogLevel('info')
    
    # Check if hping3 is installed
    if os.system('which hping3 > /dev/null') != 0:
        info('*** Error: hping3 is not installed. Please install it using:\n')
        info('*** sudo apt-get install hping3\n')
        sys.exit(1)
    
    # Create the network
    net = create_topology()
    
    # Simulate some normal traffic
    simulate_normal_traffic(net)
    
    # Print attack commands
    print_attack_commands()
    
    # Start CLI
    CLI(net)
    
    # Cleanup
    net.stop()