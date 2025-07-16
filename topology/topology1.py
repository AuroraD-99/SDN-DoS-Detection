#!/usr/bin/python
import threading
import random
import time
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController #Controller

class Environment(object):
    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        # controller senza monitoraggio del traffico e meccanismo di drop
        c1 = self.net.addController( 'c1', controller=RemoteController) #Controller
        c1.start()

        info("*** Adding hosts and switches\n")
        # aggiunta degli host alla rete
        self.h1 = self.net.addHost('h1', mac ='00:00:00:00:00:01', ip= '10.0.0.1')
        self.h2 = self.net.addHost('h2', mac ='00:00:00:00:00:02', ip= '10.0.0.2')
        self.h3 = self.net.addHost('h3', mac ='00:00:00:00:00:03', ip= '10.0.0.3')

        # aggiunta degli switch alla rete
        # - edge switch
        self.cpe1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.cpe2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.cpe3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        # - core switch
        self.core1 = self.net.addSwitch('s4', cls=OVSKernelSwitch)

        info("*** Adding links\n") 
        # collegamento tra il I host ed il I switch 
        self.net.addLink(self.h1, self.cpe1, bw=6, delay='0.0025ms')
        # collegamento tra il I switch e il III switch
        self.path1 = self.net.addLink(self.cpe1, self.core1, bw=3, delay='25ms')

        # collegamento tra il II host ed il II switch 
        self.net.addLink(self.h2, self.cpe2, bw=6, delay='0.0025ms')
        # collegamento tra il II switch e il III switch
        self.path2 = self.net.addLink(self.cpe2, self.core1, bw=3, delay='25ms')

        # collegamento tra il III switch e il IV switch
        self.path3 = self.net.addLink(self.core1, self.cpe3, bw=6, delay='25ms')
        # collegamento tra il IV switch ed il III host
        self.net.addLink(self.h3, self.cpe3, bw=3, delay='0.0025ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()

    def check_connectivity(self):
        "Check connectivity between hosts"
        info("*** Checking connectivity between hosts\n")
        hosts = [self.h1, self.h2, self.h3]
        for h1 in hosts:
            for h2 in hosts:
                if h1 != h2:
                    info(f"*** Pinging from {h1.name} to {h2.name}...\n")
                    result = h1.cmd(f'ping -c 4 {h2.IP()}')
                    if "0% packet loss" in result:
                        info(f"Ping between {h1.name} and {h2.name} successful!\n")
                    else:
                        info(f"Ping between {h1.name} and {h2.name} failed.\n")

if __name__ == '__main__':
    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    # Check connectivity before running the CLI
    env.check_connectivity()

    info("*** Running CLI\n")
    CLI(env.net)
