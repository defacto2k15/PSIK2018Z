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
MACADDR_S2_H2 = "00:00:00:00:00:08"

MACADDR_S3_S2 = "00:00:00:00:00:14"
MACADDR_H1_S2 = "00:00:00:00:00:02"
MACADDR_H2_S2 = "00:00:00:00:00:04"

MACADDR_S1_H2 = "00:00:00:00:00:06"
MACADDR_S1_H1 = "00:00:00:00:00:05"
MACADDR_H2_S1 = "00:00:00:00:00:03"

MACADDR_S1_S3 = "00:00:00:00:00:15"
MACADDR_S3_S1 = "00:00:00:00:00:16"
MACADDR_H1_S1 = "00:00:00:00:00:01"

OUTER_MAC = "11:11:11:11:11:11"

PORT_S3_S1 = 3
PORT_S3_S2 = 4

GROUP_ID_S1 = 1
GROUP_ID_S2 = 2
GROUP_ID_S3 = 3

INNER_CONECTIONS = [PORT_S3_S1, PORT_S3_S2]

ROUTER_PORT1 = 1
ROUTER_PORT2 = 2
UINT32_MAX = 0xffffffff

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ICMP = icmp.icmp.__name__

DEFAULT_TTL = 64
PRIORITY_FLOW_MISS_ENTRY = 1
FLOW_PRIORITY_LOW = 0x10


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global Ipv4_addr
    Ipv4_addr = namedtuple("Ipv4_addr", ["addr", "port", "mac", "switch_port"])
    global Switch_port
    Switch_port = namedtuple("SwitchPort", ["port_mac", "port_id"])
    global Switch_out_port
    Switch_out_port = namedtuple("Switch_out_port", ["out_mac", "port_id"])

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)

        self.mac_to_port = {}

        global maps
        maps = {}
        global ports
        ports = range(50000, 60000)

        global ip_to_out_port
        ip_to_out_port = {}

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

    # todo remove code duplication
    def add_src_ip_flow(self, datapath, in_port, actions, ip_proto, src_ip):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=ip_proto,
            ipv4_src=src_ip,
            in_port=in_port)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    def add_dst_ip_flow(self, datapath, in_port, actions, ip_proto, dst_ip):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=ip_proto,
            ipv4_dst=dst_ip,
            in_port=in_port)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    def add_flow_no_mac(self, datapath, in_port, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            in_port=in_port)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    def add_flow_no_mac2(self, datapath, actions, match_args, priority=None):
        ofproto = datapath.ofproto
        if priority is None:
            priority = ofproto.OFP_DEFAULT_PRIORITY

        match = datapath.ofproto_parser.OFPMatch(**match_args)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        inPort = msg.match['in_port']
        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet.ethernet)

        self.logger.debug("Packet in!: %s %s %s %s", datapath.id, inPort, etherFrame.src, etherFrame.dst)
        if datapath.id == SWITCH3_DPID:
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                self.logger.debug("ARP Switch3: Recieved at switch %s port %s ESrc %s EDst %s ARP", datapath.id, inPort,
                                  etherFrame.src, etherFrame.dst)
                self.receive_arp(datapath, packet, etherFrame, inPort)
                return 0
            elif etherFrame.ethertype == ether.ETH_TYPE_IP:
                ip_packet = packet.get_protocol(ipv4.ipv4)
                self.logger.debug("Recieved at switch %s port %s ESrc %s EDst %s IP ISrc %s IDst %s Proto %s",
                                  datapath.id, inPort, etherFrame.src,
                                  etherFrame.dst, ip_packet.src, ip_packet.dst, ip_packet.proto)

                if ip_packet.proto == 1:  # ICMP
                    icmp_packet = packet.get_protocol(icmp.icmp)
                    self.reply_icmp(icmp_packet, ip_packet, etherFrame, inPort, datapath)
                elif ip_packet.proto == 6:  # TCP
                    tcp_packet = packet.get_protocol(tcp.tcp)
                    self.pass_tcp(msg, tcp_packet, ip_packet, etherFrame)
            else:
                self.logger.debug("Drop packet")
                return 1
        else:
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                self.logger.debug("ARP Switch1/2 Recieved at switch %s port %s ESrc %s EDst %s ARP", datapath.id,
                                  inPort, etherFrame.src, etherFrame.dst)
                self.receive_arp(datapath, packet, etherFrame, inPort)
            else:
                self.logger.info("Error: message from unexpected switch of datapath %s", datapath.id)

    def reply_icmp(self, icmp_header, ipv4_header, ethernet_header, in_port, datapath):
        self.send_icmp(in_port,
                       icmp.ICMP_ECHO_REPLY,
                       icmp.ICMP_ECHO_REPLY_CODE, datapath,
                       ipv4_header, ethernet_header, icmp_data=icmp_header.data)

    # z https://mik.bme.hu/~zfaigl/QoS/scripts/qos_rest_router.py
    def send_icmp(self, in_port, icmp_type,
                  icmp_code, datapath, ipv4_header=None, ethernet_header=None, icmp_data=None, msg_data=None,
                  src_ip=None):
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
            self.send_arp(datapath, 2, OUTER_MAC, arpPacket.dst_ip, etherFrame.src, arpPacket.src_ip, inPort)
        elif arpPacket.opcode == 2:
            pass

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
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if in_port in OUTER_PORTS:  # from outer space
            ip_addr = ip_header.src
            ip_to_out_port[ip_addr] = Switch_out_port(port_id=in_port, out_mac=ethernet_header.src)

            buckets = [
                # parser.OFPBucket(
                #     weight=50,
                #     watch_port=ofproto.OFPP_ANY,
                #     watch_group=ofproto.OFPG_ANY,
                #     actions=[
                #         parser.OFPActionOutput(PORT_S3_S1)]
                # ),
                parser.OFPBucket(
                    weight=50,
                    watch_port=ofproto.OFPP_ANY,
                    watch_group=ofproto.OFPG_ANY,
                    actions=[
                        parser.OFPActionOutput(PORT_S3_S2)
                    ]
                ),
            ]
            req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, GROUP_ID_S3, buckets)
            datapath.send_msg(req)

            #self.add_flow_no_mac2(datapath, [parser.OFPActionGroup(GROUP_ID_S3)],
            #                      {'in_port': in_port, 'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP, 'ipv4_src':ip_addr} )

            data = None
            # Check the buffer_id and if needed pass the whole message down
            if message.buffer_id == 0xffffffff:
                data = message.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,
                                      in_port=in_port, actions=[parser.OFPActionOutput(PORT_S3_S2)])  # todo can tell switch to use new rule
            datapath.send_msg(out)

            self.add_src_ip_flow(datapath, in_port, [parser.OFPActionOutput(PORT_S3_S2)], inet.IPPROTO_TCP, ip_addr)
            dst_actions = [
                parser.OFPActionSetField(eth_dst=ethernet_header.src),
                parser.OFPActionSetField(ipv4_src=OUTER_IP),
                parser.OFPActionOutput(in_port)
            ]
            self.add_dst_ip_flow(datapath, PORT_S3_S1, dst_actions, inet.IPPROTO_TCP, ip_addr)
            self.add_dst_ip_flow(datapath, PORT_S3_S2, dst_actions, inet.IPPROTO_TCP, ip_addr)

        else:
            print "Error: unexpected tcp pass from one of inner ports: " + in_port

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
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info("Entered %s", datapath.id)

        # table miss-flow entry
        self.add_flow_no_mac2(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)], {}, PRIORITY_FLOW_MISS_ENTRY)
        # all arp's to controller
        self.add_flow_no_mac2(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                              {'eth_type': ether.ETH_TYPE_ARP})

        if datapath.id == SWITCH3_DPID:
            # all ping to switch3
            self.add_flow_no_mac2(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                                  {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_ICMP})
            # all tcp to controller, but with low priority
            self.add_flow_no_mac2(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                                  {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP}, FLOW_PRIORITY_LOW)
        elif datapath.id == SWITCH2_DPID:
            buckets = [
                parser.OFPBucket(
                    weight=50,
                    watch_port=ofproto.OFPP_ANY,
                    watch_group=ofproto.OFPG_ANY,
                    actions=[
                        parser.OFPActionSetField(eth_dst=MACADDR_H1_S2),
                        parser.OFPActionSetField(ipv4_dst=HOST_H1_S2_IP),
                        parser.OFPActionOutput(PORT_S2_H1)]
                ),
                # parser.OFPBucket(
                #     weight=50,
                #     watch_port=ofproto.OFPP_ANY,
                #     watch_group=ofproto.OFPG_ANY,
                #     actions=[
                #         parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
                #         parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
                #         parser.OFPActionOutput(PORT_S2_H2)
                #     ]
                # ),
            ]
            req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, GROUP_ID_S2, buckets)
            datapath.send_msg(req)
            self.add_flow_no_mac2(datapath, [parser.OFPActionGroup(GROUP_ID_S2)],
                                 {'in_port': PORT_S2_S3, 'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP})
            # self.add_flow_no_mac2(datapath, [
            #             parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
            #             parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
            #             parser.OFPActionOutput(PORT_S2_H2)],
            #                       {'in_port': PORT_S2_S3, 'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP})

            # self.add_flow_no_mac(datapath, PORT_S2_S3,
            #                      [
            #                          parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
            #                          parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
            #                          parser.OFPActionOutput(PORT_S2_H2)])


            self.add_flow_no_mac(datapath, PORT_S2_H1, [parser.OFPActionOutput(PORT_S2_S3)])
            self.add_flow_no_mac(datapath, PORT_S2_H2, [parser.OFPActionOutput(PORT_S2_S3)])

        elif datapath.id == SWITCH1_DPID:
            buckets = [
                # parser.OFPBucket(
                #     weight=50,
                #     watch_port=ofproto.OFPP_ANY,
                #     watch_group=ofproto.OFPG_ANY,
                #     actions=[
                #         parser.OFPActionSetField(eth_dst=MACADDR_H1_S1),
                #         parser.OFPActionSetField(ipv4_dst=HOST_H1_S1_IP),
                #         parser.OFPActionOutput(PORT_S1_H1)]
                # ),
                parser.OFPBucket(
                    weight=50,
                    watch_port=ofproto.OFPP_ANY,
                    watch_group=ofproto.OFPG_ANY,
                    actions=[
                        parser.OFPActionSetField(eth_dst=MACADDR_H2_S1),
                        parser.OFPActionSetField(ipv4_dst=HOST_H2_S1_IP),
                        parser.OFPActionOutput(PORT_S1_H2)
                    ]
                ),
            ]
            req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, GROUP_ID_S1, buckets)
            datapath.send_msg(req)
            self.add_flow_no_mac2(datapath, [parser.OFPActionGroup(GROUP_ID_S1)],
                                  {'in_port': PORT_S1_S3, 'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP})

            actions2 = [
                parser.OFPActionOutput(PORT_S1_S3)
            ]
            self.add_flow_no_mac(datapath, PORT_S1_H1, actions2)
            self.add_flow_no_mac(datapath, PORT_S1_H2, actions2)

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        self.logger.info("Left %s", switch)

    def send_packet_out(self, datapath, in_port, output, data, data_str=None):
        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]
        datapath.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
                                 actions=actions, data=data)
