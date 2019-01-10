# -*- coding: utf-8 -*-

from mininet.node import CPULimitedHost, DefaultController
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from subprocess import Popen, PIPE
from mininet.node import RemoteController, Controller
from functools import partial
import sys
import threading


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
        s3 = self.addSwitch('s3', dpid='0000000000000003',
                            protocols='OpenFlow13')  # switch-wtyczka miedzy siecia a kliantami

        klient1 = self.addHost('klient1', ip="10.0.10.1/8")
        klient2 = self.addHost('klient2', ip="10.0.10.2/8")

        self.addLink(h1, s1, intfName1='h1-eth-s1', intfName2='s1-eth-h1', port1=1, port2=1)
        self.addLink(h2, s1, intfName1='h2-eth-s1', intfName2='s1-eth-h2', port1=1, port2=2)

        self.addLink(h1, s2, intfName1='h1-eth-s2', intfName2='s2-eth-h1', port1=2, port2=1)
        self.addLink(h2, s2, intfName1='h2-eth-s2', intfName2='s2-eth-h2', port1=2, port2=2)

        self.addLink(klient1, s3, intfName1='k1-eth-s3', intfName2='s3-eth-k1', port1=1, port2=1)
        self.addLink(klient2, s3, intfName1='k2-eth-s3', intfName2='s3-eth-k2', port1=1, port2=2)

        self.addLink(s1, s3, port1=3, port2=3)  # s1-eth3<->s3-eth3
        self.addLink(s2, s3, port1=3, port2=4)  # s2-eth3<->s3-eth4


def configureNet(net):
    h1, h2, s3, s2, s1, k1, k2 = net.get('h1', 'h2', 's3', 's2', 's1', 'klient1', 'klient2')

    h2.intf(intf='h2-eth-s1').setIP('10.0.3.1/24')
    h2.intf(intf='h2-eth-s1').setMAC('00:00:00:00:00:03')

    h1.intf(intf='h1-eth-s1').setIP('10.0.1.1/24')
    h1.intf(intf='h1-eth-s1').setMAC('00:00:00:00:00:01')

    h1.intf(intf='h1-eth-s2').setIP('10.0.2.1/24')
    h1.intf(intf='h1-eth-s2').setMAC('00:00:00:00:00:02')

    h2.intf(intf='h2-eth-s2').setIP('10.0.4.1/24')
    h2.intf(intf='h2-eth-s2').setMAC('00:00:00:00:00:04')

    s3.intf(intf='s3-eth4').setMAC('00:00:00:00:00:14')
    s3.intf(intf='s3-eth3').setMAC('00:00:00:00:00:16')

    s2.intf(intf='s2-eth3').setMAC('00:00:00:00:00:13')
    s1.intf(intf='s1-eth3').setMAC('00:00:00:00:00:15')

    s3.intf(intf='s3-eth-k1').setMAC('00:00:00:00:00:09')
    s3.intf(intf='s3-eth-k2').setMAC('00:00:00:00:00:07')

    s2.intf(intf='s2-eth-h1').setMAC('00:00:00:00:00:07')
    s2.intf(intf='s2-eth-h2').setMAC('00:00:00:00:00:08')

    s1.intf(intf='s1-eth-h2').setMAC('00:00:00:00:00:06')
    s1.intf(intf='s1-eth-h1').setMAC('00:00:00:00:00:05')

    k1.intf(intf='k1-eth-s3').setIP('10.0.10.1/8')
    k1.intf(intf='k1-eth-s3').setMAC('00:00:00:00:00:11')

    k2.intf(intf='k2-eth-s3').setIP('10.0.10.2/8')
    k2.intf(intf='k2-eth-s3').setMAC('00:00:00:00:00:12')

class testerClass():
    def __init__(self,net):
        import time
        self.net = net
        self.networkAdress = "10.0.1.1" 	#Jaki jest adres do serverów z zewnątrz?
    def Stopping(self,obiekt,switch=""):
        print "Stopping!!"
        # TUTAJ PISZE JAK SIE WYLACZA SWITCHE I INTEREFEJSY
        o = self.net.get(obiekt)
        isinstance(o, mininet.node.switch):
            o.stop()
        else:
            o.cmd('ifconfig '+obiekt+'-eth-'+switch+' down')
    def Starting(self,obiekt,switch=""):
        print "Starting!!"
        # TUTAJ PISZE JAK SIE włącza
        o = self.net.get(obiekt)  
        isinstance(o, mininet.node.switch):
            o.start('')
        else:
            o.cmd('ifconfig '+obiekt+'-eth-'+switch+' up')
        
    def normalTest(self,duration,raportName):
        print 'initiating normal test'
        h1, h2, s1, s2, s3, k1, k2 = net.get('h1', 'h2', 's1', 's2', 's3', 'klient1', 'klient2')
        h1.sendCmd('python testServer.py 10.0.1.1 10.0.1.2')
        h2.sendCmd('python testServer.py 10.0.2.1 10.0.2.2')
        k1.sendCmd('python testClient.py '+self.networkAdress+" 1")
        k2.sendCmd('python testClient.py '+self.networkAdress+" 2")
        time.sleep(duration)
        k1.sendInt()
        k2.sendInt()
        h1.sendInt()
        h2.sendInt()
        with open(raportName,'w') as raport, open('log_1.txt','r') as log1,open('log_2.txt','r') as log2:
                raport.write("\tlog1\n")
                raport.write(log1.read())
                raport.write("\tlog2\n")
                raport.write(log2.read())
        print 'normal test finished'
    def stressTest(self,duration,raportName,downName,downName2):
        print 'initiating stress test {0} - {1}'.format(downName,downName2)
        h1, h2, s1, s2, s3, k1, k2 = net.get('h1', 'h2', 's1', 's2', 's3', 'klient1', 'klient2')
        h1.sendCmd('python testServer.py 10.0.1.1 10.0.1.2')
        h2.sendCmd('python testServer.py 10.0.2.1 10.0.2.2')
        k1.sendCmd('python testClient.py '+self.networkAdress+" 1")
        k2.sendCmd('python testClient.py '+self.networkAdress+" 2")
        time.sleep(duration//2)
        self.Stopping(downName,downName2)
        time.sleep(duration-duration//2)

        k1.sendInt()
        k2.sendInt()
        h1.sendInt()
        h2.sendInt()

        self.Starting(downName,downName2)
        with open(raportName,'w') as raport, open('log_1.txt','r') as log1,open('log_2.txt','r') as log2:
                raport.write("\tlog1\n")
                raport.write(log1.read())
                raport.write("\tlog2\n")
                raport.write(log2.read())
        print 'stress test finished'
    def allStressTests(self,duration,raportName):
        downList=[('s1',""),('s2',""),('h1','s1'),('h1','s2'),('h2','s1'),('h2','s2')]
        for d in downList:
            self.stressTest(duration,"{1}-{2}_{0}".format(raportName,d[0],d[1]),d[0],d[1])
def run():
    myTopo = SimpleTopo()
    myController = partial(RemoteController, ip='192.168.74.5', port=6633)
    net = Mininet(topo=myTopo, host=CPULimitedHost,
                  controller=myController)
    configureNet(net)
    net.start()

	#Testy z użyciem testerClass
	tester = testerClass()
	tester.normalTest(60,'zwyklyTest.txt')
	tester.allStressTests(60,'stressTest.txt')
	
    def Stopping():
        print "Stopping!!"
        # TUTAJ PISZE JAK SIE WYLACZA SWITCHE I INTEREFEJSY
        # net.get('s1').stop()
        net.get('s2').stop()
        net.get('h1').cmd('ifconfig h1-eth-s1 down')
        # net.get('h1').cmd('ifconfig h1-eth-s2 down')
        # net.get('h2').cmd('ifconfig h2-eth-s1 down')
        # net.get('h2').cmd('ifconfig h2-eth-s2 down')
    def Starting():
        print "Starting!!"
        # TUTAJ PISZE JAK SIE włącza
        # net.get('s1').start('')
        # net.get('s2').start('')
        net.get('h1').cmd('ifconfig h1-eth-s1 up')
        # net.get('h1').cmd('ifconfig h1-eth-s2 up')
        # net.get('h2').cmd('ifconfig h2-eth-s1 up')
        # net.get('h2').cmd('ifconfig h2-eth-s2 up')

    threading.Timer(10.0, Stopping).start()
    threading.Timer(20.0, Starting).start()

    klient1 = net.get('klient1')
    klient1.cmd('ping 10.0.5.1 -c1')

    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/server/h1')
    h1.cmd('python -m SimpleHTTPServer 80 &')

    h2 = net.get('h2')
    h2.cmd('cd /home/mininet/server/h2')
    h2.cmd('python -m SimpleHTTPServer 80 &')

    if False:  # nieważne, do testów
        cli = CLI(net, script='echo "lol"')
        CLI.do_xterm(cli, "h1 klient1")

        for line in sys.stdin:
            print line
    else:
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
	