#!/usr/bin/python

"""
A simple minimal topology script for Mininet.

Based in part on examples in the [Introduction to Mininet] page on the Mininet's
project wiki.

[Introduction to Mininet]: https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#apilevels

"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
# from topo import topo2file, FatTree, FatTreeOutBand

class MinimalTopo( Topo ):
    "Minimal topology with a single switch and two hosts"

    def build( self ):
        # Create two hosts.
        h0 = self.addHost('h000')
        h1 = self.addHost('h001')
        h2 = self.addHost('h002')
        h3 = self.addHost('h003')
        h4 = self.addHost('h004')
        h5 = self.addHost('h005')
        h6 = self.addHost('h006')
        h7 = self.addHost('h007')

        # Create a switch
        s1 = self.addSwitch( 's001', protocols='OpenFlow10' )
        s2 = self.addSwitch( 's002', protocols='OpenFlow10' )
        s3 = self.addSwitch( 's003', protocols='OpenFlow10' )
        s4 = self.addSwitch( 's004', protocols='OpenFlow10' )


        # Add links between the switch and each host
        # linkopts = dict(bw=1000)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s2, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s4)

        self.addLink(s1, h0)
        self.addLink(s1, h1)

        self.addLink(s2, h2)
        self.addLink(s2, h3)

        self.addLink(s3, h4)
        self.addLink(s3, h5)

        self.addLink(s4, h6)
        self.addLink(s4, h7)

def runMinimalTopo():
    "Bootstrap a Mininet network using the Minimal Topology"

    # Create an instance of our topology
    topo = MinimalTopo()

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1', port=6633, protocols='OpenFlow10' ),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True )

    net.get('h000').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h000').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h000').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h000').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h000').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h000').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h000').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h000').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h001').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h001').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h001').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h001').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h001').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h001').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h001').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h001').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h002').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h002').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h002').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h002').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h002').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h002').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h002').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h002').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h003').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h003').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h003').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h003').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h003').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h003').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h003').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h003').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h004').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h004').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h004').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h004').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h004').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h004').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h004').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h004').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h005').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h005').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h005').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h005').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h005').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h005').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h005').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h005').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h006').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h006').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h006').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h006').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h006').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h006').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h006').cmd('arp -s 10.0.0.8 00:00:00:00:00:08')
    net.get('h006').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    net.get('h007').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h007').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h007').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')
    net.get('h007').cmd('arp -s 10.0.0.5 00:00:00:00:00:05')
    net.get('h007').cmd('arp -s 10.0.0.6 00:00:00:00:00:06')
    net.get('h007').cmd('arp -s 10.0.0.7 00:00:00:00:00:07')
    net.get('h007').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h007').cmd('arp -s 10.0.0.9 00:00:00:00:00:09')

    # c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6643, protocols='OpenFlow10')
    # c2 = net.addController('c2', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow10')
   # c2 = net.addController('c2', controller=RemoteController, ip="127.0.0.1", port=6633)

    # Actually start the network
    net.start()

    # Drop the user in to a CLI so user can run commands.
    CLI( net )

    # After the user exits the CLI, shutdown the network.
    net.stop()

if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel( 'info' )
    runMinimalTopo()

# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'minimal': MinimalTopo
}
