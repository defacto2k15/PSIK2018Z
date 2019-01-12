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
import os
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


class NetworkSituation:
    def __init__(self, switch_state,interface_state ):
        self.switch_state = switch_state
        self.interface_state = interface_state

class TestingNetworkStateManager:
    def __init__(self, init_state, net):
        self.current_state = init_state
        self.net = net

    def change_switch_state(self, switch_index, new_state, cli_object):
        switch_name = ''
        if switch_index is 1:
            switch_name = 's1'
        elif switch_index is 2:
            switch_name = 's2'

        if new_state is True:
            cli_object.do_switch(switch_name+' start')
        else:
            cli_object.do_switch(switch_name + ' stop')

    def change_interface_state(self, interface_index, new_state):
        switch_name = ''
        interface_name = ''
        if interface_index is 1:
            switch_name = 's1'
            interface_name = 'h1-eth-s1'
        elif interface_index is 2:
            switch_name = 's1'
            interface_name = 'h1-eth-s2'
        elif interface_index is 3:
            switch_name = 's2'
            interface_name = 'h2-eth-s1'
        elif interface_index is 4:
            switch_name = 's2'
            interface_name = 'h2-eth-s2'

        if new_state is True:
            self.net.get(switch_name).cmd('ifconfig '+interface_name+' up')
        else:
            self.net.get(switch_name).cmd('ifconfig '+interface_name+' down')

    def change_to_state(self, next_state, cli_object):
        for i in {1,2}:
            if self.current_state.switch_state[i] != next_state.switch_state[i]:
                self.change_switch_state(i, next_state.switch_state[i], cli_object)

        for i in {1, 2, 3, 4}:
            if self.current_state.interface_state[i] != next_state.interface_state[i]:
                self.change_interface_state(i, next_state.interface_state[i])

        self.current_state = next_state

def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def wait_until_process_ended(pids):
    any_alive = True
    while any_alive:
        any_alive = False
        message = 'Waiting for processes: [ '
        for pid in pids:
            if check_pid(pid):
                message = message + str(pid) + ' '
                any_alive = True
        message = message + ' ]'
        print message

def test1(cli_object, net):
    print "Starting test1"
    os.system('mkdir -p /home/mininet/testing/test1')
    os.system('rm -r /home/mininet/testing/test1/*')

    k1 = net.get('klient1')
    k2 = net.get('klient2')

    pids = []

    for i in range(2):
        k1.cmd('~/go/bin/tcpgoon run 10.0.5.1 80 -y -c 1000 -t 20000 > /home/mininet/testing/test1/k1-'+str(i)+'.txt &')
        pids.append( k1.lastPid)

    # for i in range(0,5):
    #     k2.cmd('~/go/bin/tcpgoon run 10.0.5.1 80 -y -c 1000 -t 20000 > /home/mininet/testing/test1/k2-'+str(i)+'.txt &')
    #     pids.append(k2.lastPid)

    wait_until_process_ended(pids)

def run():
    cli_object = None

    myTopo = SimpleTopo()
    myController = partial(RemoteController, ip='192.168.74.5', port=6633)
    #myController = partial(RemoteController, ip='127.0.0.1', port=6633)
    net = Mininet(topo=myTopo, host=CPULimitedHost,
                  controller=myController)
    configureNet(net)
    net.start()

    network_situation = NetworkSituation(switch_state = {1:True, 2:True}, interface_state = {1:True, 2:True, 3:True, 4:True})

    network_state_manager = TestingNetworkStateManager(network_situation, net)

    def Stopping():
        print "ChangingState!!"
        network_state_manager.change_to_state(NetworkSituation(switch_state = {1:True, 2:False},
                                                               interface_state = {1:True, 2:True, 3:False, 4:True}),cli_object )

    def Starting():
        print "ChangingState22!!"
        network_state_manager.change_to_state(NetworkSituation(switch_state = {1:True, 2:True},
                                                               interface_state = {1:True, 2:True, 3:True, 4:True}),cli_object )

    #threading.Timer(10.0, Stopping).start()
    #threading.Timer(20.0, Starting).start()


    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/server/h1')
    h1.cmd('python -m SimpleHTTPServer 80 &')

    h2 = net.get('h2')
    h2.cmd('cd /home/mininet/server/h2')
    h2.cmd('python -m SimpleHTTPServer 80 &')

    if False:  # nieważne, do testów
        cli = CLI(net, script='echo "lol"')
        CLI.do_xterm(cli, "h2 klient1")

        for line in sys.stdin:
            print line
    elif True:
        cli = CLI(net, script='echo "lol"')
        cli_object = cli

        threading.Timer(5.0, lambda : test1(cli_object, net)).start()

        CLI(net)
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

    clear_commands = ['sudo ip link delete s1-eth-h1', 'sudo ip link delete s1-eth-h2',
                      'sudo ip link delete s2-eth-h1', 'sudo ip link delete s2-eth-h2',
                     'sudo ip link delete s3-eth-k1', 'sudo ip link delete s3-eth-k2'
                      ]
    for command in clear_commands:
        os.system(command)

    p = Popen(['sudo', 'mn', '-c'], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    p.wait()
    if p.returncode != 0:
        print('returned value: ', p.returncode, " stdout:", p.stdout.read(), "stderr:", p.stderr.read())
    run()
