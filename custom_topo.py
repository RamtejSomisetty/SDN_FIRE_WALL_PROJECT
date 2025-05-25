#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, CPULimitedHost
from mininet.link import TCLink
from mininet.log import setLogLevel

class MultiSwitchTopo(Topo):
    """Three switches connected, each with 2-3 hosts."""
    def build(self):
        # Add switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')

        # Connect switches in a triangle topology
        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        self.addLink(switch3, switch1)

        # Add hosts to each switch
        for i in range(1, 4):
            for j in range(1, 4):
                # Use string formatting instead of f-strings
                host = self.addHost('h%d%d' % (i, j))
                self.addLink(host, locals()['switch%d' % i])

def run():
    topo = MultiSwitchTopo()
    net = Mininet(
        topo=topo,
        autoSetMacs=True,
        host=CPULimitedHost,
        link=TCLink,
        autoStaticArp=False,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633)
    )

    net.start()
    print("Network is up. Launching CLI...")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()