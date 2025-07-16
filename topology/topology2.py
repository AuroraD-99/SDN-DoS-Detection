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
        # Aggiunta degli Host (6 legittimi, 2 attaccanti)
        # Host Legittimi (distribuiti su diversi switch edge)
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')
        self.h5 = self.net.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5')
        self.h6 = self.net.addHost('h6', mac='00:00:00:00:00:06', ip='10.0.0.6')
        self.h7 = self.net.addHost('h7', mac='00:00:00:00:00:07', ip='10.0.0.7') # Attaccante 1 su s8
        self.h8 = self.net.addHost('h8', mac='00:00:00:00:00:08', ip='10.0.0.8') # Attaccante 2 su s9

        # Aggiunta degli Switch (Totale: 10)
        # Livello Core (2 switch)
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)

        # Livello di Aggregazione (4 switch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch) # Collegato a s1
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch) # Collegato a s1
        self.s5 = self.net.addSwitch('s5', cls=OVSKernelSwitch) # Collegato a s2
        self.s6 = self.net.addSwitch('s6', cls=OVSKernelSwitch) # Collegato a s2

        # Livello Edge (4 switch)
        self.s7 = self.net.addSwitch('s7', cls=OVSKernelSwitch) # Collegato a s3
        self.s8 = self.net.addSwitch('s8', cls=OVSKernelSwitch) # Collegato a s4
        self.s9 = self.net.addSwitch('s9', cls=OVSKernelSwitch) # Collegato a s5
        self.s10 = self.net.addSwitch('s10', cls=OVSKernelSwitch) # Collegato a s6

        
        info("*** Adding links\n") 

        # Collegamenti Core Layer (alta banda, basso ritardo per la dorsale)
        self.net.addLink(self.s1, self.s2, bw=9, delay='0.0025ms') 

        # Collegamenti Aggregation Layer a Core Layer (banda media, ritardo medio)
        self.net.addLink(self.s1, self.s3, bw=9, delay='0.025ms')
        self.net.addLink(self.s1, self.s4, bw=9, delay='0.025ms')
        self.net.addLink(self.s2, self.s5, bw=9, delay='0.025ms')
        self.net.addLink(self.s2, self.s6, bw=9, delay='0.025ms')

        # Collegamenti Edge Layer a Aggregation Layer (banda media, ritardo medio)
        self.net.addLink(self.s3, self.s7, bw=6, delay='0.25ms')
        self.net.addLink(self.s4, self.s8, bw=6, delay='0.25ms')
        self.net.addLink(self.s5, self.s9, bw=6, delay='0.25ms')
        self.net.addLink(self.s6, self.s10, bw=6, delay='0.25ms')

        # Collegamenti Host a Switch Edge (alta banda, ritardo molto basso)
        # Distribuzione Host Legittimi
        self.net.addLink(self.h1, self.s7, bw=3, delay='25ms')
        self.net.addLink(self.h2, self.s7, bw=3, delay='25ms') # h1 e h2 sullo stesso switch edge
        self.net.addLink(self.h3, self.s8, bw=3, delay='25ms')
        self.net.addLink(self.h4, self.s9, bw=3, delay='25ms')
        self.net.addLink(self.h5, self.s10, bw=3, delay='25ms')
        self.net.addLink(self.h6, self.s10, bw=3, delay='25ms') # h5 e h6 sullo stesso switch edge

        # Distribuzione Host Attaccanti (su switch edge diversi)
        self.net.addLink(self.h7, self.s8, bw=3, delay='25ms') # a1 su s8 (condivide con h3)
        self.net.addLink(self.h8, self.s9, bw=3, delay='25ms') # a2 su s9 (condivide con h4)

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
