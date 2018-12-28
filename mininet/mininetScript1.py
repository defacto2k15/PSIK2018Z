# -*- coding: utf-8 -*-

from mininet.node import CPULimitedHost, DefaultController
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from subprocess import Popen, PIPE
from mininet.node import RemoteController, Controller
from functools import partial


# from testServer import testHTTPRequestHandler

# odpalamy sudo -E python <nazwa skryptu>

class SimpleTopo(Topo):
    "SimpleTopo"

    def __init__(self, **opts):
        Topo.__init__(self, **opts)

    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13')  # switch-wtyczka miedzy siecia a kliantami

        klient1 = self.addHost('klient1', ip="10.0.3.1/8")
        klient2 = self.addHost('klient2', ip="10.0.3.2/8")

        #self.addLink(h1, s2, intfName1='h1-eth-s2', intfName2='s2-eth-h1', port1=2, port2=1)
        self.addLink(h2, s2, intfName1='h2-eth-s2', intfName2='s2-eth-h2', port1=2, port2=2)

        self.addLink(h1, s1, intfName1='h1-eth-s1', intfName2='s1-eth-h1', port1=1, port2=1)
        #self.addLink(h2, s1, intfName1='h2-eth-s1', intfName2='s1-eth-h2', port1=1, port2=2)

        self.addLink(klient1, s3, intfName1='k1-eth-s3', intfName2='s3-eth-k1', port1=1, port2=1)
        self.addLink(klient2, s3, intfName1='k2-eth-s3', intfName2='s3-eth-k2', port1=1, port2=2)

        self.addLink(s1, s3, port1=3, port2=3) #s1-eth3<->s3-eth3
        self.addLink(s2, s3, port1=3, port2=4) #s2-eth3<->s3-eth4


def configureNet(net):
    h1, h2, s3, s2, s1,  k1, k2 = net.get('h1', 'h2',  's3', 's2', 's1', 'klient1', 'klient2')

    # h2.intf(intf='h2-eth-s1').setIP('10.0.2.1/8')
    # h2.intf(intf='h2-eth-s1').setMAC('00:00:00:00:00:03')

    # h1.intf(intf='h1-eth-s2').setIP('10.0.1.2/8')
    # h1.intf(intf='h1-eth-s2').setMAC('00:00:00:00:00:02')

    h2.intf(intf='h2-eth-s2').setIP('10.0.2.2/8')
    h2.intf(intf='h2-eth-s2').setMAC('00:00:00:00:00:04')

    h1.intf(intf='h1-eth-s1').setIP('10.0.1.1/8')
    h1.intf(intf='h1-eth-s1').setMAC('00:00:00:00:00:01')

    s3.intf(intf='s3-eth4').setMAC('00:00:00:00:00:14')
    s3.intf(intf='s3-eth3').setMAC('00:00:00:00:00:16')

    s2.intf(intf='s2-eth3').setMAC('00:00:00:00:00:13')
    s1.intf(intf='s1-eth3').setMAC('00:00:00:00:00:15')

    s3.intf(intf='s3-eth-k1').setMAC('00:00:00:00:00:09')
    s3.intf(intf='s3-eth-k2').setMAC('00:00:00:00:00:07')

    # s2.intf(intf='s2-eth-h1').setMAC('00:00:00:00:00:07')
    s2.intf(intf='s2-eth-h2').setMAC('00:00:00:00:00:08')

    # s1.intf(intf='s1-eth-h2').setMAC('00:00:00:00:00:06')
    s1.intf(intf='s1-eth-h1').setMAC('00:00:00:00:00:05')

    k1.intf(intf='k1-eth-s3').setIP('10.0.3.1/8')
    k1.intf(intf='k1-eth-s3').setMAC('00:00:00:00:00:11')

    k2.intf(intf='k2-eth-s3').setIP('10.0.3.2/8')
    k2.intf(intf='k2-eth-s3').setMAC('00:00:00:00:00:12')

def run():
    myTopo = SimpleTopo()
    myController = partial(RemoteController, ip='192.168.74.5', port=6633)
    net = Mininet(topo=myTopo, host=CPULimitedHost,
                  controller=myController)
    configureNet(net)
    net.start()

    klient1 = net.get('klient1')
    klient1.cmd('ping 10.0.5.1 -c1')
    
    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/server/h1')
    h1.cmd('python -m SimpleHTTPServer 80 &')

    h2 = net.get('h2')
    h2.cmd('cd /home/mininet/server/h2')
    h2.cmd('python -m SimpleHTTPServer 80 &')

    CLI(net)

    # POLECENIA DO TESTOWANIA
    # klient1 ping 10.0.5.1 -c1
    # klient2 ping 10.0.5.1 -c1
    #
    # klient1 wget -O - -T 1 -t 1 10.0.5.1
    # klient2 wget -O - -T 1 -t 1 10.0.5.1
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    p = Popen(['sudo', 'mn', '-c'], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    p.wait()
    if p.returncode != 0:
        print('returned value: ', p.returncode, " stdout:", p.stdout.read(), "stderr:", p.stderr.read())
    run()
