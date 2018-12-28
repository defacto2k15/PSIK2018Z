"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from collections import namedtuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event

SWITCH3_DPID = 3
SWITCH2_DPID = 2
SWITCH1_DPID = 1

OUTER_IP = "10.0.5.1"

HOST_H1_S1_IP = "10.0.1.1"
HOST_H1_S2_IP = "10.0.1.2"
HOST_H2_S1_IP = "10.0.2.1"
HOST_H2_S2_IP = "10.0.2.2"

PORT_S3_K1 = 1
PORT_S3_K2 = 2
OUTER_PORTS = [PORT_S3_K1, PORT_S3_K2]

PORT_S2_H1 = 1
PORT_S2_H2 = 2
PORT_S2_S3 = 3

PORT_S1_H1 = 1
PORT_S1_H2 = 2
PORT_S1_S3 = 3

MACADDR_S2_S3 = "00:00:00:00:00:13"
MACADDR_S2_H1 = "00:00:00:00:00:07"
MACADDR_S2_H2 = "00:00:00:00:00:02"

MACADDR_S3_S2 = "00:00:00:00:00:14"
MACADDR_H1_S2 = "00:00:00:00:01:01"
MACADDR_H2_S2 = "00:00:00:00:00:04"

MACADDR_S1_H2 = "00:00:00:00:00:06"
MACADDR_S1_H1 = "00:00:00:00:00:05"
MACADDR_H2_S1 = "00:00:00:00:00:03"

MACADDR_S1_S3 = "00:00:00:00:00:15"
MACADDR_S3_S1 = "00:00:00:00:00:16"
MACADDR_H1_S1 = "00:00:00:00:00:01"


INNER_PORTS = [3,4]

global Switch_link
Switch_link = namedtuple("Switch_link", ["port_id", "switch_port_mac", "other_port_mac"])

INNER_CONECTIONS = [Switch_link(port_id=3, switch_port_mac=MACADDR_S3_S1, other_port_mac=MACADDR_S1_S3),
                    Switch_link(port_id=4, switch_port_mac=MACADDR_S3_S2, other_port_mac=MACADDR_S2_S3)]


ROUTER_PORT1 = 1
ROUTER_PORT2 = 2
UINT32_MAX = 0xffffffff


ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ICMP = icmp.icmp.__name__

DEFAULT_TTL = 64

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global Ipv4_addr
    Ipv4_addr = namedtuple("Ipv4_addr", ["addr", "port", "mac", "switch_port"])
    global Switch_port
    Switch_port = namedtuple("SwitchPort", ["port_mac", "port_id"])

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)

        self.mac_to_port = {}

        global maps
        maps = {}
        global ports
        ports = range(50000, 60000)

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            in_port=in_port,
            eth_dst=dst, eth_src=src)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        inPort = msg.match['in_port']
        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet.ethernet)

        if datapath.id == SWITCH3_DPID:
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                self.logger.debug("Recieved at switch %s port %s ESrc %s EDst %s ARP", datapath.id, inPort, etherFrame.src, etherFrame.dst)
                self.receive_arp(datapath, packet, etherFrame, inPort)
                return 0
            elif etherFrame.ethertype == ether.ETH_TYPE_IP:
                ip_packet = packet.get_protocol(ipv4.ipv4)
                self.logger.debug("Recieved at switch %s port %s ESrc %s EDst %s IP ISrc %s IDst %s Proto %s", datapath.id, inPort, etherFrame.src,
                                  etherFrame.dst, ip_packet.src, ip_packet.dst, ip_packet.proto)

                if ip_packet.proto == 1: #ICMP
                    icmp_packet = packet.get_protocol(icmp.icmp)
                    self.reply_icmp(icmp_packet, ip_packet, etherFrame, inPort, datapath)
                elif ip_packet.proto == 6: #TCP
                    tcp_packet = packet.get_protocol(tcp.tcp)
                    self.pass_tcp(  msg, tcp_packet, ip_packet, etherFrame)
            else:
                self.logger.debug("Drop packet")
                return 1
        elif datapath.id == SWITCH2_DPID or datapath.id == SWITCH1_DPID:
            self.logger.info("SWITCH2 OR SWITCH1: packet in from switch2 or switch1")
            ofproto = datapath.ofproto

            pkt =  Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)

            dst = eth.dst
            src = eth.src

            dpid = datapath.id  # datapath.id to identyfikator kontrollera
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.match['in_port'])

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.match['in_port']

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.match['in_port'], dst, src, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                actions=actions, data=data)
            datapath.send_msg(out)
        else:
            self.logger.info("Error: message from unexpected switch of datapath %s", datapath.id)


    def reply_icmp(self, icmp_header, ipv4_header, ethernet_header, in_port, datapath):
        self.send_icmp(in_port,
                             icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE, datapath,
                              ipv4_header, ethernet_header, icmp_data=icmp_header.data)

    # z https://mik.bme.hu/~zfaigl/QoS/scripts/qos_rest_router.py
    def send_icmp(self, in_port, icmp_type,
                  icmp_code, datapath, ipv4_header=None, ethernet_header=None, icmp_data=None, msg_data=None, src_ip=None):
        # Generate ICMP reply packet
        csum = 0
        offset = ethernet.ethernet._MIN_LEN

        ether_proto = ether.ETH_TYPE_IP

        eth = ethernet_header
        e = ethernet.ethernet(eth.src, eth.dst, ether_proto)

        if icmp_data is None and msg_data is not None:
            ip_datagram = msg_data[offset:]
            if icmp_type == icmp.ICMP_DEST_UNREACH:
                icmp_data = icmp.dest_unreach(data_len=len(ip_datagram),
                                              data=ip_datagram)
            elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
                icmp_data = icmp.TimeExceeded(data_len=len(ip_datagram),
                                              data=ip_datagram)

        ic = icmp.icmp(icmp_type, icmp_code, csum, data=icmp_data)

        ip = ipv4_header
        if src_ip is None:
            src_ip = ip.dst
        ip_total_length = ip.header_length * 4 + ic._MIN_LEN
        if ic.data is not None:
            ip_total_length += ic.data._MIN_LEN
            if ic.data.data is not None:
                ip_total_length += + len(ic.data.data)
        i = ipv4.ipv4(ip.version, ip.header_length, ip.tos,
                      ip_total_length, ip.identification, ip.flags,
                      ip.offset, DEFAULT_TTL, inet.IPPROTO_ICMP, csum,
                      src_ip, ip.src)

        pkt = packet.Packet()
        pkt.add_protocol(e)

        pkt.add_protocol(i)
        pkt.add_protocol(ic)
        pkt.serialize()

        # Send packet out
        self.send_packet_out(datapath, in_port, datapath.ofproto.OFPP_IN_PORT,
                             pkt.data, data_str=str(pkt))


    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            pass


    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        our_mac = datapath.ports[inPort].hw_addr
        if inPort in OUTER_PORTS and arp_dstIp == OUTER_IP:
            srcMac = our_mac
            outPort = inPort
        elif inPort in  INNER_PORTS and srcIp == OUTER_IP:
            srcMac = our_mac
            outPort = inPort
        else:
            self.logger.debug("unknown arp requst received !")

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        targetMac = dstMac
        targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def pass_tcp(self, message, tcp_header, ip_header, ethernet_header):
        datapath = message.datapath
        in_port = message.match['in_port']
        tcp_src_port = tcp_header.src_port
        parser = datapath.ofproto_parser

        if in_port in OUTER_PORTS: #from outer space
            ipv4_addr = Ipv4_addr(addr=ip_header.src, port=tcp_src_port, mac=ethernet_header.src,
                                  switch_port=Switch_port(port_mac=ethernet_header.dst, port_id=in_port))
            if ipv4_addr in maps:
                port = maps[ipv4_addr]
            else:
                port = ports.pop()
                maps[ipv4_addr] = port
                maps[port] = ipv4_addr
                print "Created mapping: %s %s to %s %s" % (ipv4_addr.addr, ipv4_addr.port, OUTER_IP, port)

            #TODO: lepszy wybor sciezki
            #inner_path = INNER_CONECTIONS[port % 2]
            inner_path = INNER_CONECTIONS[0]

            actions = [
                parser.OFPActionSetField(eth_src=inner_path.switch_port_mac),
                parser.OFPActionSetField( eth_dst=inner_path.other_port_mac, ),
                parser.OFPActionSetField(ipv4_src=OUTER_IP),
                parser.OFPActionSetField(tcp_src=port),
                parser.OFPActionOutput(inner_path.port_id)
            ]
            data = None
            # Check the buffer_id and if needed pass the whole message down
            if message.buffer_id == 0xffffffff:
                data = message.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,
                                      in_port=in_port, actions=actions)
            datapath.send_msg(out)
        else:
            dst_port = tcp_header.dst_port
            if dst_port in maps:
                ipv4_addr = maps[dst_port]
            else:
                print "Dropping msg as dst is not understood"
                return
            actions = [
                parser.OFPActionSetField(eth_src=ipv4_addr.switch_port.port_mac),
                parser.OFPActionSetField( eth_dst=ipv4_addr.mac),
                parser.OFPActionSetField(ipv4_src=OUTER_IP),
                parser.OFPActionSetField(ipv4_dst=ipv4_addr.addr),
                parser.OFPActionSetField(tcp_dst=ipv4_addr.port),
                parser.OFPActionOutput(ipv4_addr.switch_port.port_id)
            ]

            data = None
            # Check the buffer_id and if needed pass the whole message down
            if message.buffer_id == 0xffffffff:
                data = message.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,
                                      in_port=in_port, actions=actions)
            datapath.send_msg(out)
            return

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        datapath = switch.dp

        self.logger.info("Entered %s", datapath.id)
        if datapath.id == SWITCH2_DPID:
            self.logger.info("Proactively pushing rules to switch 2");
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            buckets = [
                parser.OFPBucket(
                    weight=50,
                    watch_port=PORT_S2_H1,
                    watch_group=ofproto.OFPG_ANY,
                    actions=[
                        parser.OFPActionSetField(eth_dst=MACADDR_H1_S2),
                        parser.OFPActionSetField( ipv4_dst=HOST_H1_S2_IP),
                        parser.OFPActionOutput(PORT_S2_H1)]
                ),
                parser.OFPBucket(
                    weight=50,
                    watch_port=PORT_S2_H2,
                    watch_group=ofproto.OFPG_ANY,
                    actions=[
                        parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
                        parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
                        parser.OFPActionOutput(PORT_S2_H2)
                    ]
                ),
            ]
            group_id = 1
            #req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, group_id, buckets)
            #datapath.send_msg(req)

            actions = [
                parser.OFPActionSetField(eth_src=MACADDR_S2_H2),
                parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
                parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
                parser.OFPActionOutput(PORT_S2_H2)
            ]
            self.add_flow(datapath, PORT_S2_S3, MACADDR_S2_S3, MACADDR_S3_S2, actions )
        elif datapath.id == SWITCH1_DPID:
            self.logger.info("Proactively pushing rules to switch 1");
            parser = datapath.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=MACADDR_S1_H1),
                parser.OFPActionSetField(eth_dst=MACADDR_H1_S1),
                parser.OFPActionSetField(ipv4_dst=HOST_H1_S1_IP),
                parser.OFPActionOutput(PORT_S1_H1)
            ]
            self.add_flow(datapath, PORT_S1_S3, MACADDR_S1_S3, MACADDR_S3_S1, actions )

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        self.logger.info("Left %s", switch)


    def send_packet_out(self,datapath, in_port, output, data, data_str=None):
        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]
        datapath.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
                                actions=actions, data=data)