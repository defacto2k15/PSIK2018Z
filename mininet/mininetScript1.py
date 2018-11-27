from mininet.node import CPULimitedHost, DefaultController
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from subprocess import Popen, PIPE
from mininet.node import RemoteController, Controller
from functools import partial

# odpalamy sudo -E python <nazwa skryptu>

class SimpleTopo(Topo):
    "SimpleTopo"
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3') #switch-wtyczka miedzy siecia a kliantami

        klient1 = self.addHost('klient1',  ip="10.0.3.1/8")
        klient2 = self.addHost('klient2',  ip="10.0.3.2/8")

        self.addLink(h1, s1, intfName1='h1-eth-s1', intfName2='s1-eth-h1')
        self.addLink(h1, s2, intfName1='h1-eth-s2', intfName2='s2-eth-h1')

        self.addLink(h2, s1, intfName1='h2-eth-s1', intfName2='h2-eth-s1')
        self.addLink(h2, s2, intfName1='h2-eth-s2', intfName2='h2-eth-s2')

        self.addLink(klient1, s3,  intfName1='k1-eth-s3', intfName2='s3-eth-k1')
        self.addLink(klient2, s3,  intfName1='k2-eth-s3', intfName2='s3-eth-k2')

        self.addLink(s1,s3)
        self.addLink(s2,s3)

def configureNet(net):
    h1, h2, s1, s2, s3, k1, k2 = net.get('h1', 'h2', 's1', 's2', 's3', 'klient1', 'klient2')

    h1.intf(intf='h1-eth-s1').setIP( '10.0.1.1/8')
    h1.intf(intf='h1-eth-s2').setIP('10.0.1.2/8')

    h2.intf(intf='h2-eth-s1').setIP( '10.0.2.1/8')
    h2.intf(intf='h2-eth-s2').setIP('10.0.2.2/8')

    k1.intf(intf='k1-eth-s3').setIP( '10.0.3.1/8')
    k2.intf(intf='k2-eth-s3').setIP('10.0.4.1/8')


def run():
    myTopo = SimpleTopo()
    #myController=DefaultController
    myController=partial(RemoteController, ip='192.168.74.5', port=6633)
    net = Mininet(topo=myTopo, host=CPULimitedHost,
                  controller=myController,
                  autoSetMacs = True)
    configureNet(net)
    net.start()
    net.pingAll()
    #CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    p = Popen(['sudo', 'mn', '-c'], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    p.wait()
    if p.returncode != 0:
        print('returned value: ',p.returncode, " stdout:" , p.stdout.read() , "stderr:", p.stderr.read())
    run()