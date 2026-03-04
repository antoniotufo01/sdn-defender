#!/usr/bin/env python3
"""
topology_wide.py

Topologia Mininet per test SDN Defender:
 - 9 switch (core + aggregation + edge)
 - 6 host (h1..h6)
 - Attaccanti suggeriti: h1, h3, h5 (collegati ad edge switches diversi)
 - Vittime/legittimi: h2, h4, h6
 - Usa RemoteController (default 127.0.0.1:6653)
 - Optional: start_traffic() per lanciare iperf3 (richiede iperf3 installato)
"""

from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.topo import Topo
import time

class WideTopo(Topo):
    def build(self):
        # Core
        s1 = self.addSwitch('s1')  # core

        # Aggregation layer
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Edge layer (each aggregation connects to two edge switches)
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')
        s9 = self.addSwitch('s9')

        # Hosts (6 hosts)
        h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')  # attacker candidate
        h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')  # victim candidate
        h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')  # attacker candidate
        h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')  # victim candidate
        h5 = self.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5')  # attacker candidate
        h6 = self.addHost('h6', mac='00:00:00:00:00:06', ip='10.0.0.6')  # victim candidate

        # --- Connect core to aggregation (high bw, low delay) ---
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='1ms')
        self.addLink(s1, s3, cls=TCLink, bw=100, delay='1ms')
        self.addLink(s1, s4, cls=TCLink, bw=100, delay='1ms')

        # --- Connect aggregation to edge (moderate bw) ---
        self.addLink(s2, s5, cls=TCLink, bw=50, delay='5ms')
        self.addLink(s2, s6, cls=TCLink, bw=50, delay='5ms')

        self.addLink(s3, s7, cls=TCLink, bw=50, delay='5ms')
        self.addLink(s3, s8, cls=TCLink, bw=50, delay='5ms')

        self.addLink(s4, s9, cls=TCLink, bw=50, delay='5ms')

        # --- Connect edge switches to hosts (edge access links) ---
        # Distribute hosts so attackers are on different edge switches
        self.addLink(h1, s5, cls=TCLink, bw=10, delay='0.5ms')  # attacker 1 (s5)
        self.addLink(h2, s6, cls=TCLink, bw=10, delay='0.5ms')  # victim 1 (s6)

        self.addLink(h3, s7, cls=TCLink, bw=10, delay='0.5ms')  # attacker 2 (s7)
        self.addLink(h4, s8, cls=TCLink, bw=10, delay='0.5ms')  # victim 2 (s8)

        self.addLink(h5, s9, cls=TCLink, bw=10, delay='0.5ms')  # attacker 3 (s9)
        self.addLink(h6, s9, cls=TCLink, bw=10, delay='0.5ms')  # victim 3 (s9) -- same edge as attacker 3 to allow mixed scenarios

        # Note: s9 holds both h5 and h6 (intentionally) to test mixed-case; attackers still distributed across s5,s7,s9.

def start_network(controller_ip='127.0.0.1', controller_port=6653, start_cli=True, auto_iperf=False):
    """
    Avvia la topologia collegata a RemoteController(controller_ip:controller_port).
    Se auto_iperf True, lancerà iperf3 server su vittime e attacchi UDP dagli attacker.
    """
    setLogLevel('info')
    info('*** Creating network\n')
    topo = WideTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller=lambda name: RemoteController(name, ip=controller_ip, port=controller_port), link=TCLink, autoSetMacs=True)

    info('*** Starting network\n')
    net.start()

    # Raccogli handle utili
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')

    info('\n*** Host summary:\n')
    for h in (h1, h2, h3, h4, h5, h6):
        info(f'  {h.name}: {h.IP()}  {h.MAC()}\n')

    if auto_iperf: #TEST AUTOMATICI ATTUALMENTE DISABILITATI PERCHè auto_iperf=False
        info('*** Starting iperf3 servers on victims (h2,h4,h6)\n')
        # Start iperf3 server on victims (background)
        for hv in (h2, h4, h6):
            hv.cmd('pkill -f iperf3 || true')
            hv.cmd('nohup iperf3 -s > /tmp/iperf3_%s_server.log 2>&1 &' % hv.name)
        time.sleep(1)
        info('*** Launching UDP attack streams from h1,h3,h5 -> victims\n')
        # Attacker streams (UDP high bandwidth, run in background)
        # target mapping: h1->h2, h3->h4, h5->h6
        attacks = [
            (h1, h2.IP()),
            (h3, h4.IP()),
            (h5, h6.IP()),
        ]
        for ha, target_ip in attacks:
            # -u UDP, -b bandwidth (e.g., 100M), -t duration (seconds)
            ha.cmd('nohup iperf3 -c %s -u -b 100M -t 120 > /tmp/iperf3_%s_client.log 2>&1 &' % (target_ip, ha.name))
        info('*** Iperf traffic started (check /tmp/iperf3_* on hosts)\n')

    info('*** Network ready. If your controller is running, it should see 9 switches.\n')

    if start_cli:
        CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    # Modifica questi valori se il tuo controller è su un IP diverso
    CONTROLLER_IP = '127.0.0.1'
    CONTROLLER_PORT = 6653

    # Se voglio far partire il traffico di test (iperf3), metti auto_iperf=True
    start_network(controller_ip=CONTROLLER_IP, controller_port=CONTROLLER_PORT, start_cli=True, auto_iperf=False)
