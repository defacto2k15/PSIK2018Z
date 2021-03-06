"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

from collections import namedtuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
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
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

SWITCH3_DPID = 3
SWITCH2_DPID = 2
SWITCH1_DPID = 1

HOST_H1_S1_IP = "10.0.1.1"
HOST_H1_S2_IP = "10.0.2.1"
HOST_H2_S1_IP = "10.0.3.1"
HOST_H2_S2_IP = "10.0.4.1"

SWITCH_S1_H1_IP = "10.0.1.2"
SWITCH_S2_H1_IP = "10.0.2.2"
SWITCH_S1_H2_IP = "10.0.3.2"
SWITCH_S2_H2_IP = "10.0.4.2"

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

PORT_S3_S1 = 3
PORT_S3_S2 = 4

GROUP_ID_S1 = 1
GROUP_ID_S2 = 2
GROUP_ID_S3 = 3

ROUTER_PORT1 = 1
ROUTER_PORT2 = 2
UINT32_MAX = 0xffffffff

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ICMP = icmp.icmp.__name__

DEFAULT_TTL = 64
PRIORITY_FLOW_MISS_ENTRY = 1
FLOW_PRIORITY_LOW = 0x10
OUT_FLOW_PRIORITY = 0x20

OUTFLOW_IDLE_TIMEOUT = 10  # 0 means infinite


class PathState:
    def __init__(self, host_interface, switch):
        self.host_interface = host_interface
        self.switch = switch


switch_app_name = 'simple_switch_api_app'
rest_url = '/change_public_address'
rest_password = 'asdf'
S3_MAX_FREE_FLOWS = 800

class TopologyAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyAPI, self).__init__(req, link, data, **config)
        self.app = data[switch_app_name]


    @route('simpleswitch', rest_url, methods=['POST'])
    def _websocket_handler(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)
        if 'password' not in body or not body['password'] == rest_password:
            print "Failed parsing password"
            return Response(status=400)
        if 'address' not in body:
            print "Failed parsing address"
            return Response(status=400)

        self.app.change_public_ip(body['address'])

        return Response(status=200)

class ManualOutflowInfo:
    def __init__(self, ip, port, ethernet_dst):
        self.ip = ip
        self.port = port
        self.ethernet_dst = ethernet_dst

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

        self.paths_state = {SWITCH_S1_H1_IP: PathState(True, False), SWITCH_S1_H2_IP: PathState(True, False),
                            SWITCH_S2_H1_IP: PathState(True, False), SWITCH_S2_H2_IP: PathState(True, False)}
        self.s3_group_created = False
        self.OUTER_IP = "10.0.5.1"

        wsgi = kwargs['wsgi']
        wsgi.register(TopologyAPI, {switch_app_name: self})
        self.S3FreeFlows = S3_MAX_FREE_FLOWS
        self.tcp_port_to_ip = {}

    def send_message_to_table(sel, datapath, in_port, message):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        data = None
        # Check the buffer_id and if needed pass the whole message down
        if message.buffer_id == 0xffffffff:
            data = message.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,
                                  in_port=in_port,
                                  actions=[parser.OFPActionOutput(
                                      ofproto.OFPP_TABLE)])
        datapath.send_msg(out)

    def add_flow(self, datapath, actions, match_args, priority=None, idle_timeout=0, command=None):
        ofproto = datapath.ofproto
        if priority is None:
            priority = ofproto.OFP_DEFAULT_PRIORITY
        if command is None:
            command = ofproto.OFPFC_ADD

        match = datapath.ofproto_parser.OFPMatch(**match_args)

        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=command, idle_timeout=idle_timeout, hard_timeout=0,
            priority=priority,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match_args, priority=None):
        ofproto = datapath.ofproto
        if priority is None:
            priority = ofproto.OFP_DEFAULT_PRIORITY

        match = datapath.ofproto_parser.OFPMatch(**match_args)

        mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,
                                                 0,
                                                 ofproto.OFPFC_DELETE,
                                                 0, 0,
                                                 1,
                                                 ofproto.OFPCML_NO_BUFFER,
                                                 ofproto.OFPP_ANY,
                                                 ofproto.OFPG_ANY, 0,
                                                 match, [])
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        inPort = msg.match['in_port']
        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet.ethernet)

        #self.logger.debug("Packet in!: %s %s %s %s", datapath.id, inPort, etherFrame.src, etherFrame.dst)
        if datapath.id == SWITCH3_DPID:
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                self.logger.debug("ARP Switch3: Recieved at switch %s port %s ESrc %s EDst %s ARP", datapath.id, inPort,
                                  etherFrame.src, etherFrame.dst)
                self.receive_arp(datapath, packet, etherFrame, inPort)
                return 0
            elif etherFrame.ethertype == ether.ETH_TYPE_IP:
                ip_packet = packet.get_protocol(ipv4.ipv4)
                #self.logger.debug("Recieved at switch %s port %s ESrc %s EDst %s IP ISrc %s IDst %s Proto %s",
                                 # datapath.id, inPort, etherFrame.src,
                                  #etherFrame.dst, ip_packet.src, ip_packet.dst, ip_packet.proto)

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

    def send_packet_out(self, datapath, in_port, output, data, data_str=None):
        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]
        datapath.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
                                 actions=actions, data=data)

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            dst_ip = arpPacket.dst_ip
            if (datapath.id == SWITCH3_DPID and dst_ip == self.OUTER_IP) \
                    or (datapath.id == SWITCH1_DPID and dst_ip in (SWITCH_S1_H1_IP, SWITCH_S1_H2_IP)) \
                    or (datapath.id == SWITCH2_DPID and dst_ip in (SWITCH_S2_H1_IP, SWITCH_S2_H2_IP)):
                self.send_arp(datapath, 2, datapath.ports[inPort].hw_addr, arpPacket.dst_ip, etherFrame.src,
                              arpPacket.src_ip, inPort)
            else:
                self.logger.error("Unexpected ARP request from dpid %s dst_ip %s", datapath.id, dst_ip)
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

    def message_s3_group(self, datapath, action_type):
        ofproto = datapath.ofproto

        if action_type is ofproto.OFPGC_ADD:
            self.s3_group_created = True
        elif self.s3_group_created is False:
            self.logger.debug("S3 group is not yet created")
            return

        parser = datapath.ofproto_parser

        buckets = []
        if self.paths_state[SWITCH_S1_H1_IP].switch is True and self.paths_state[
            SWITCH_S1_H1_IP].host_interface is True:
            buckets.append(parser.OFPBucket(
                weight=50,
                watch_port=ofproto.OFPP_ANY,
                watch_group=ofproto.OFPG_ANY,
                actions=[
                    parser.OFPActionSetField(ipv4_src=SWITCH_S1_H1_IP),
                    parser.OFPActionOutput(PORT_S3_S1),
                ],
            ))

        if self.paths_state[SWITCH_S1_H2_IP].switch is True and self.paths_state[
            SWITCH_S1_H2_IP].host_interface is True:
            buckets.append(parser.OFPBucket(
                weight=50,
                watch_port=ofproto.OFPP_ANY,
                watch_group=ofproto.OFPG_ANY,
                actions=[
                    parser.OFPActionSetField(ipv4_src=SWITCH_S1_H2_IP),
                    parser.OFPActionOutput(PORT_S3_S1),
                ],
            ))

        if self.paths_state[SWITCH_S2_H1_IP].switch is True and self.paths_state[
            SWITCH_S2_H1_IP].host_interface is True:
            buckets.append(parser.OFPBucket(
                weight=50,
                watch_port=ofproto.OFPP_ANY,
                watch_group=ofproto.OFPG_ANY,
                actions=[
                    parser.OFPActionSetField(ipv4_src=SWITCH_S2_H1_IP),
                    parser.OFPActionOutput(PORT_S3_S2)
                ]
            ))

        if self.paths_state[SWITCH_S2_H2_IP].switch is True and self.paths_state[
            SWITCH_S2_H2_IP].host_interface is True:
            buckets.append(parser.OFPBucket(
                weight=50,
                watch_port=ofproto.OFPP_ANY,
                watch_group=ofproto.OFPG_ANY,
                actions=[
                    parser.OFPActionSetField(ipv4_src=SWITCH_S2_H2_IP),
                    parser.OFPActionOutput(PORT_S3_S2)
                ]
            ))

        req = parser.OFPGroupMod(datapath, action_type, ofproto.OFPGT_SELECT, GROUP_ID_S3, buckets)
        datapath.send_msg(req)

    def pass_tcp(self, message, tcp_header, ip_header, ethernet_header):
        datapath = message.datapath
        in_port = message.match['in_port']
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        tcp_src = tcp_header.src_port
        tcp_dst = tcp_header.dst_port

        #self.logger.debug("TCP PORT IS %s", tcp_header.src_port)

        if in_port in OUTER_PORTS:  # from outer space
            if not ip_header.dst == self.OUTER_IP:
                self.logger.debug("Destination ip of packet:%s is wrong, dropping", ip_header.dst)
                return
            ip_addr = ip_header.src

            if self.S3FreeFlows >= 10:
                self.add_flow(datapath,
                              [parser.OFPActionGroup(GROUP_ID_S3)],
                              {'in_port': in_port, 'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP,
                               'ipv4_src': ip_addr,
                               'tcp_src': tcp_src}
                              , idle_timeout=OUTFLOW_IDLE_TIMEOUT, priority=OUT_FLOW_PRIORITY+1)

                dst_actions = [
                    parser.OFPActionSetField(eth_dst=ethernet_header.src),
                    parser.OFPActionSetField(ipv4_src=self.OUTER_IP),
                    parser.OFPActionSetField(ipv4_dst=ip_addr),
                    parser.OFPActionOutput(in_port)
                ]

                self.add_flow(datapath,
                              dst_actions,
                              {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP,
                               'tcp_dst': tcp_src}, idle_timeout=OUTFLOW_IDLE_TIMEOUT, priority=OUT_FLOW_PRIORITY)

                self.send_message_to_table(datapath, in_port, message)
                self.S3FreeFlows -= 2
            else:
                self.logger.debug("Manual routing, free count %s", self.S3FreeFlows)
                self.tcp_port_to_ip[tcp_src] = ManualOutflowInfo(ip=ip_addr, port=in_port, ethernet_dst=ethernet_header.src)
                actions = [parser.OFPActionGroup(GROUP_ID_S3)]
                data = None
                # Check the buffer_id and if needed pass the whole message down
                if message.buffer_id == 0xffffffff:
                    data = message.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,in_port=in_port,actions=actions)
                datapath.send_msg(out)
        else:
            if tcp_dst not in self.tcp_port_to_ip:
                self.logger.error("Error: unexpected tcp pass from one of inner ports: %s", in_port)
                return
            else:
                info = self.tcp_port_to_ip[tcp_dst]
                dst_actions = [
                    parser.OFPActionSetField(eth_dst=info.ethernet_dst),
                    parser.OFPActionSetField(ipv4_src=self.OUTER_IP),
                    parser.OFPActionSetField(ipv4_dst=info.ip),
                    parser.OFPActionOutput(info.port)
                ]
                data = None
                # Check the buffer_id and if needed pass the whole message down
                if message.buffer_id == 0xffffffff:
                    data = message.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data,in_port=in_port,actions=dst_actions)
                datapath.send_msg(out)


    def change_public_ip(self, new_public_ip):
        self.OUTER_IP = new_public_ip

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
            self.logger.info("port modified %s state %s at switch %s ", port_no, msg.desc.state, msg.datapath.id)

            state = msg.desc.state
            if msg.datapath.id is SWITCH1_DPID:
                if port_no is PORT_S1_H1:
                    if state is 1:
                        self.paths_state[SWITCH_S1_H1_IP].host_interface = False
                    elif state is 0:
                        self.paths_state[SWITCH_S1_H1_IP].host_interface = True
                    else:
                        self.logger.error("Unexpected state of port")
                        return
                elif port_no is PORT_S1_H2:
                    if state is 1:
                        self.paths_state[SWITCH_S1_H2_IP].host_interface = False
                    elif state is 0:
                        self.paths_state[SWITCH_S1_H2_IP].host_interface = True
                    else:
                        self.logger.error("Unexpected state of port")
                        return
                else:
                    self.logger.error("Unexpected port_no")
                    return

            elif msg.datapath.id is SWITCH2_DPID:
                if port_no is PORT_S2_H1:
                    if state is 1:
                        self.paths_state[SWITCH_S2_H1_IP].host_interface = False
                    elif state is 0:
                        self.paths_state[SWITCH_S2_H1_IP].host_interface = True
                    else:
                        self.logger.error("Unexpected state of port")
                        return
                elif port_no is PORT_S2_H2:
                    if state is 1:
                        self.paths_state[SWITCH_S2_H2_IP].host_interface = False
                    elif state is 0:
                        self.paths_state[SWITCH_S2_H2_IP].host_interface = True
                    else:
                        self.logger.error("Unexpected state of port")
                        return
            elif msg.datapath.id is SWITCH3_DPID:
                return
            else:
                self.logger.error("Unexpected datapath")

            dp = self.dpset.get(SWITCH3_DPID)
            self.message_s3_group(dp, dp.ofproto.OFPGC_MODIFY)

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
        self.add_flow(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)], {}, PRIORITY_FLOW_MISS_ENTRY)
        # all arp's to controller
        self.add_flow(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                      {'eth_type': ether.ETH_TYPE_ARP})

        if datapath.id == SWITCH3_DPID:

            self.S3FreeFlows = S3_MAX_FREE_FLOWS
            self.paths_state = {SWITCH_S1_H1_IP: PathState(True, False), SWITCH_S1_H2_IP: PathState(True, False),
                                SWITCH_S2_H1_IP: PathState(True, False), SWITCH_S2_H2_IP: PathState(True, False)}
            self.tcp_port_to_ip = {}

            self.s3_datapath = datapath
            # all ping to switch3
            self.add_flow(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                          {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_ICMP})
            # all tcp to controller, but with low priority
            self.add_flow(datapath, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
                          {'eth_type': ether.ETH_TYPE_IP, 'ip_proto': inet.IPPROTO_TCP}, FLOW_PRIORITY_LOW)

            # add s3 routing group
            self.message_s3_group(datapath, ofproto.OFPGC_ADD)

        elif datapath.id == SWITCH2_DPID:
            self.paths_state[SWITCH_S2_H1_IP].switch = True
            self.paths_state[SWITCH_S2_H2_IP].switch = True

            if switch.ports[PORT_S2_H1]._state is 0:
                self.paths_state[SWITCH_S2_H1_IP].host_interface = True
            else:
                self.paths_state[SWITCH_S2_H1_IP].host_interface = False
            if switch.ports[PORT_S2_H2]._state is 0:
                self.paths_state[SWITCH_S2_H2_IP].host_interface = True
            else:
                self.paths_state[SWITCH_S2_H2_IP].host_interface = False

            if self.dpset.get(SWITCH3_DPID):
                dp = self.dpset.get(SWITCH3_DPID)
                self.message_s3_group(dp, dp.ofproto.OFPGC_MODIFY)

            self.add_flow(datapath,
                          [
                              parser.OFPActionSetField(eth_dst=MACADDR_H1_S2),
                              parser.OFPActionSetField(ipv4_dst=HOST_H1_S2_IP),
                              parser.OFPActionOutput(PORT_S2_H1)
                          ],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S2_S3, 'ipv4_src': SWITCH_S2_H1_IP})
            self.add_flow(datapath,
                          [
                              parser.OFPActionSetField(eth_dst=MACADDR_H2_S2),
                              parser.OFPActionSetField(ipv4_dst=HOST_H2_S2_IP),
                              parser.OFPActionOutput(PORT_S2_H2)
                          ],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S2_S3, 'ipv4_src': SWITCH_S2_H2_IP})

            self.add_flow(datapath, [parser.OFPActionOutput(PORT_S2_S3)],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S2_H1})
            self.add_flow(datapath, [parser.OFPActionOutput(PORT_S2_S3)],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S2_H2})

        elif datapath.id == SWITCH1_DPID:
            self.paths_state[SWITCH_S1_H1_IP].switch = True
            self.paths_state[SWITCH_S1_H2_IP].switch = True

            if switch.ports[PORT_S1_H1]._state is 0:
                self.paths_state[SWITCH_S1_H1_IP].host_interface = True
            else:
                self.paths_state[SWITCH_S1_H1_IP].host_interface = False
            if switch.ports[PORT_S1_H2]._state is 0:
                self.paths_state[SWITCH_S1_H2_IP].host_interface = True
            else:
                self.paths_state[SWITCH_S1_H2_IP].host_interface = False

            if self.dpset.get(SWITCH3_DPID):
                dp = self.dpset.get(SWITCH3_DPID)
                self.message_s3_group(dp, dp.ofproto.OFPGC_MODIFY)

            self.add_flow(datapath,
                          [
                              parser.OFPActionSetField(eth_dst=MACADDR_H1_S1),
                              parser.OFPActionSetField(ipv4_dst=HOST_H1_S1_IP),
                              parser.OFPActionOutput(PORT_S1_H1)
                          ],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S1_S3, 'ipv4_src': SWITCH_S1_H1_IP})
            self.add_flow(datapath,
                          [
                              parser.OFPActionSetField(eth_dst=MACADDR_H2_S1),
                              parser.OFPActionSetField(ipv4_dst=HOST_H2_S1_IP),
                              parser.OFPActionOutput(PORT_S1_H2)
                          ],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S1_S3, 'ipv4_src': SWITCH_S1_H2_IP})

            self.add_flow(datapath, [parser.OFPActionOutput(PORT_S1_S3)],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S1_H1})
            self.add_flow(datapath, [parser.OFPActionOutput(PORT_S1_S3)],
                          {'eth_type': ether.ETH_TYPE_IP, 'in_port': PORT_S1_H2})

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        self.logger.info("Left %s", switch)
        if switch is SWITCH1_DPID:
            self.paths_state[SWITCH_S1_H1_IP].switch = False
            self.paths_state[SWITCH_S1_H2_IP].switch = False
        elif switch is SWITCH2_DPID:
            self.paths_state[SWITCH_S2_H1_IP].switch = False
            self.paths_state[SWITCH_S2_H2_IP].switch = False
        dp = self.dpset.get(SWITCH3_DPID)
        self.message_s3_group(dp, dp.ofproto.OFPGC_MODIFY)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
        if dp.id == SWITCH3_DPID:
            self.S3FreeFlows += 1