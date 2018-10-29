from mininet.node import CPULimitedHost
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, Controller
from mininet.cli import CLI
from functools import partial


# odpalamy sudo -E python <nazwa skryptu>

class SimpleTopo(Topo):
    "SimpleTopo"
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')

        s2 = self.addSwitch('s2')
        klient = self.addHost('klient')

        self.addLink(h1, s1)
        self.addLink(h1, s2)
        self.addLink(h2, s1)
        self.addLink(h2, s2)

        self.addLink(klient, s1)
        self.addLink(klient, s2)

        self.addLink(klient,s2)
#       self.addLink(s1,s2)

def run():
    myTopo = SimpleTopo()
    net = Mininet(topo=myTopo, host=CPULimitedHost,
                  controller=partial(RemoteController, ip='192.168.74.5', port=6633))
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()