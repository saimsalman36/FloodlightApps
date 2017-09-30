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
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Create a switch
        s1 = self.addSwitch( 's001')


        # Add links between the switch and each host
        # linkopts = dict(bw=1000)

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

def runMinimalTopo():
    "Bootstrap a Mininet network using the Minimal Topology"

    # Create an instance of our topology
    topo = MinimalTopo()

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True )

    net.get('h1').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h1').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h1').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')

    net.get('h2').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h2').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h2').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')

    net.get('h3').cmd('arp -s 10.0.0.5 00:00:00:00:00:01')
    net.get('h3').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h3').cmd('arp -s 10.0.0.4 00:00:00:00:00:04')

    net.get('h4').cmd('arp -s 10.0.0.5 00:00:00:00:00:01')
    net.get('h4').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h4').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')

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
