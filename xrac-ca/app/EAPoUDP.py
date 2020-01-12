# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import ipv6
from ryu.lib.packet import udp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import eap
from ryu.lib.packet import radius
from custom_py_logger import logger

import os  # to generate the random challenge
import socket  # to send/receive udp packet to/from the RADIUS server

# configurations and definitions
UDP_PROTO = 17
ICMPV6_PROTO = 58
BUFFER_SIZE = 4096  # for the UDP socket
EAP_OVER_UDP_PORT = 50000
REAUTH_TIMEOUT = 15  # default re-authentication-interval = 10 seconds
SOCKET_TIMEOUT = 2
MY_IP = "2001:db8::1"
MY_ADDR = "e6:c6:91:ff:65:48"
INTERFACE_NAME = "mybridge"
BLACKLISTED_IPS = ["2001:db8::bb:0"]
USERS = {"user": {"pw": "password", "allowed_ips": BLACKLISTED_IPS},
         "user2": {"pw": "password", "allowed_ips": BLACKLISTED_IPS,
                   "image-id": "sha256:c30178c5239f2937c21c261b0365efcda25be4921ccb95acd63beeeb78786f27"}}
RADIUS_ADDR = ("127.0.0.1", 1812)
RADIUS_SECRET = "testing123"


class EAPoverUDP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(EAPoverUDP, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

        self.mac_to_port = {}
        self.identifier_to_identity = {}  # challenge_or_state

        self.my_ip = MY_IP
        self.my_addr = MY_ADDR
        self.blacklisted_ips = BLACKLISTED_IPS
        self.identifier = -1

        # log-level
        # 0. error, warning, info(2), debug(2)  (default)
        # 1. error, warning, info(2)
        # 2. error, warning
        # 3. error
        # 4. (nothing)
        self.log = logger.Log(self.__class__.__name__, level=1)
        self.log.debug("initialized\n"
                       "    mac_to_port = {}\n"
                       "          my_ip = {}\n"
                       "blacklisted_ips = {}\n"
                       "     identifier = {}"
                       .format(self.mac_to_port, self.my_ip, self.blacklisted_ips, self.identifier))

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def controller_change_handler(self, ev):
        datapath = ev.dp
        # dpid = datapath.id
        if ev.enter:
            self.log.debug("event: datapath join  dpid: {}".format(datapath.id))
            # install proactive flow-rules
            self.remove_all_table_flows(datapath)
            self.install_table_miss_flow(datapath)
            for black_ipv6 in self.blacklisted_ips:
                self.install_drop_ipv6_flows(datapath, black_ipv6)
                self.install_allow_ipv6_flows(datapath, self.my_ip, black_ipv6)
            self.install_eapoudp_start_flow(datapath)
            self.install_allow_icmpv6_neighbor(datapath)

            self.log.debug("finished with installing proactive flow-rules")
        else:
            self.log.debug("event: datapath leave dpid: {}".format(datapath.id))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # msg = ev.msg
        #
        # self.logger.debug('OFPSwitchFeatures received: '
        #                   'datapath_id=0x%016x n_buffers=%d '
        #                   'n_tables=%d auxiliary_id=%d '
        #                   'capabilities=0x%08x',
        #                   msg.datapath_id, msg.n_buffers, msg.n_tables,
        #                   msg.auxiliary_id, msg.capabilities)
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        #########################

        # dump packet
        self.dump_packet(pkt)

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt is not None and udp_pkt.dst_port == EAP_OVER_UDP_PORT:
            return self.do_eap_over_udp(datapath, in_port, pkt)

        #########################

        # from here: normal simple_switch_13 behvior

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def send_packet(self, datapath, port, pkt):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=ofp.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout,
                                    buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def remove_all_table_flows(self, datapath, table_id=0):
        """
        Removes all OFP flows from table
        from https://sourceforge.net/p/ryu/mailman/message/32333352/
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        empty_match = parser.OFPMatch()
        empty_instruction = []

        # ryu.ofproto.ofproto_v1_3_parser.OFPFlowMod(datapath, cookie=0, cookie_mask=0, table_id=0, command=0, idle_timeout=0, hard_timeout=0, priority=32768, buffer_id=4294967295, out_port=0, out_group=0, flags=0, match=None, instructions=None)
        flow_mod = parser.OFPFlowMod(datapath=datapath,
                                     table_id=table_id,
                                     command=ofp.OFPFC_DELETE,
                                     buffer_id=ofp.OFPCML_NO_BUFFER,
                                     out_port=ofp.OFPP_ANY,
                                     out_group=ofp.OFPG_ANY,
                                     match=empty_match,
                                     instructions=empty_instruction)
        datapath.send_msg(flow_mod)

        self.log.info("deleted all flow entries in table: {}".format(table_id))

    def install_table_miss_flow(self, datapath):
        """
        install table-miss flow entry

        We specify NO BUFFER to max_len of the output action due to
        OVS bug. At this moment, if we specify a lesser number, e.g.,
        128, OVS will send Packet-In with invalid buffer_id and
        truncated packet data. In that case, we cannot output packets
        correctly.  The bug has been fixed in OVS v2.1.0.
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        empty_match = parser.OFPMatch()
        controller_actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, empty_match, controller_actions)
        self.log.info("installed table-miss flow entry")

    def install_drop_ipv6_flows(self, datapath, ipv6):
        """
        drop all ipv6 traffic to/from given ipv6-address
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        empty_action = []
        clear_action_instruction = [parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, empty_action)]

        # dst direction
        dst_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                    ipv6_dst=ipv6)
        dst_mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=10,
                                    match=dst_match,
                                    flags=ofp.OFPFF_SEND_FLOW_REM,
                                    instructions=clear_action_instruction)
        datapath.send_msg(dst_mod)

        # src direction
        src_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                    ipv6_src=ipv6)
        src_mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=10,
                                    match=src_match,
                                    flags=ofp.OFPFF_SEND_FLOW_REM,
                                    instructions=clear_action_instruction)
        datapath.send_msg(src_mod)

        self.log.info("installed drop-all-IPv6-traffic flows for: {}".format(ipv6))

    def install_allow_ipv6_flows(self, datapath, ipv6_1, ipv6_2, hard_timeout=0):
        """
        allow ipv6 traffic between ipv6_1 and ipv6_2
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        normal_action = [parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]

        # ipv6_1 -> ipv6_2
        match_1to2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                     ipv6_src=ipv6_1,
                                     ipv6_dst=ipv6_2)
        self.add_flow(datapath, 20, match_1to2, normal_action, hard_timeout=hard_timeout)

        # ipv6_1 <- ipv6_2
        match_2to1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                     ipv6_src=ipv6_2,
                                     ipv6_dst=ipv6_1)
        self.add_flow(datapath, 20, match_2to1, normal_action, hard_timeout=hard_timeout)

        self.log.info("installed allow-ipv6 flows for: {} and {} hard_timeout={}".format(ipv6_1, ipv6_2, hard_timeout))

    def install_eapoudp_start_flow(self, datapath):
        """
        install EAPoverUDPv6 start flow

        all UDPv6 packets to the EAP_OVER_UDP_START_PORT are explicit for the controller
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                ip_proto=UDP_PROTO,
                                udp_dst=EAP_OVER_UDP_PORT)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 30, match, actions)

        self.log.info("installed EAPoUDPv6-start flows for port: {}".format(EAP_OVER_UDP_PORT))

    def install_allow_icmpv6_neighbor(self, datapath):
        """
        install ICMPv6 Neighbor Solicitation (135) and Advertisement (136) flow

        allow this types, it's like ARP for IPv6
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        normal_action = [parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]

        # Solicitation
        match_solicit = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                        ip_proto=ICMPV6_PROTO,
                                        icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT)
        self.add_flow(datapath, 30, match_solicit, normal_action)

        # Solicitation
        match_advert = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                                       ip_proto=ICMPV6_PROTO,
                                       icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)
        self.add_flow(datapath, 30, match_advert, normal_action)

        self.log.info("installed ICMPv6 Neighbor Solicitation/Advertisment flows")

    def do_eap_over_udp(self, datapath, in_port, pkt):
        """
        the big EAPoverUDP function to authenticate und authorize the supplicant
        handel the incoming EAPoUDP packets and perform RADIUS-requests or check the local user db
        :param datapath:
        :param in_port:
        :param pkt: incoming EAPoUDP packet
        :return: nothing
        """
        self.log.info2("got EAPoUDP packet from mac={} ip={}"
                       .format(pkt.protocols[0].src, pkt.protocols[1].src))
        # time for a new identifier
        idf = self.get_new_identifier()

        # generate response packet
        resp_pkt = self.generate_response_packet(pkt)

        # a empty UDP packet indicates the EAPoUDP-START
        if len(pkt.protocols) == 3:
            resp_pkt.add_protocol(eap.eap(eap_code=eap.EAP_CODE_REQUEST,
                                          identifier=idf,
                                          eap_type=eap.EAP_TYPE_IDENTITY))
            self.log.info2("0: sending IDENTITY REQUEST with identifier={}".format(idf))
        else:
            # check if last protocol is a valid EAP packet
            # eap_pkt = pkt.get_protocol(eap.eap)
            eap_pkt = eap.eap.parser(pkt.protocols[-1])
            if eap_pkt is None:
                self.log.warning("got no EAP packet? ignoring...")
                return
            # we are the authenticator, so we only accept RESPONSE packets
            if eap_pkt.eap_code != eap.EAP_CODE_RESPONSE:
                self.log.warning("only accept RESPONSE packets (code={}, identifier={})! ignoring..."
                                 .format(eap_pkt.eap_code, eap_pkt.identifier))
                return

            # normal EAP packet, but which type of?
            self.log.debug2("EAPoUDP packet dump: {}".format(eap_pkt))
            # IDENTITY
            if eap_pkt.eap_type == eap.EAP_TYPE_IDENTITY:
                identity = eap_pkt.data.decode("utf-8")
                self.log.info2("1: receiving IDENTITY: {}, with identifier={}".format(identity, eap_pkt.identifier))

                # local or RADIUS user?
                if identity in USERS.keys():  # local user
                    self.log.debug("local user")
                    # maybe type request, currently only MD5CHALLENGE are supported
                    challenge = os.urandom(16)  # random 16 bytes challenge
                    eap_pkt = eap.eap(eap_code=eap.EAP_CODE_REQUEST,
                                      identifier=idf,
                                      eap_type=eap.EAP_TYPE_MD5CHALLENGE,
                                      challenge=challenge)
                    self.identifier_to_identity[idf] = \
                        {'identity': identity, 'challenge': challenge}
                else:  # RADIUS user
                    self.log.debug("RADIUS user")
                    eap_pkt, reply_msg = self.get_challenge_by_identity(identity, eap_pkt, idf)
                    if reply_msg:
                        self.send_notification(pkt, datapath, in_port, reply_msg)
                    if not eap_pkt:
                        self.send_failure(resp_pkt, idf, datapath, in_port)
                        return
                # challenge successfully created, send it to the supplicant
                resp_pkt.add_protocol(eap_pkt)
                self.log.info2("2: sending MD5CHALLENGE REQUEST to supplicant with identifier={}".format(idf))

            # CHALLENGE
            elif eap_pkt.eap_type == eap.EAP_TYPE_MD5CHALLENGE:
                self.log.info2("3: receiving MD5CHALLENGE RESPONSE with identifier={}".format(eap_pkt.identifier))
                if eap_pkt.identifier not in self.identifier_to_identity.keys():
                    self.log.warning("unknown identifier={}! ignoring...".format(eap_pkt.identifier))
                    return

                id_chl = self.identifier_to_identity[eap_pkt.identifier]

                # prepare data
                d = self.parse_extra_data(eap_pkt.data)
                self.log.debug2("supplicant extra data: {}".format(d))
                # check data
                if 'ip' not in d.keys():
                    self.log.warning("no supplicant ip address transferred for identity={}!! aborting..."
                                     .format(id_chl['identity']))
                    self.send_failure(resp_pkt, idf, datapath, in_port)
                    return

                # local or RADIUS user?
                if 'challenge' in id_chl.keys():  # local user
                    self.log.debug("local user")
                    if eap_pkt.challenge != eap.eap.calc_md5_challenge(eap_pkt.identifier,
                                                                       USERS[id_chl['identity']]['pw'],
                                                                       id_chl['challenge']):
                        self.log.warning("Login for local user {} failed! Please check your username and password."
                                         .format(id_chl['identity']))
                        self.send_notification(pkt, datapath, in_port,
                                               "Login for {} failed! Please check your username and password."
                                               .format(id_chl['identity']))
                        self.send_failure(resp_pkt, idf, datapath, in_port)
                        return
                    if 'image-id' in USERS[id_chl['identity']].keys():
                        if 'image-id' not in d.keys():
                            self.log.warning("no supplicant image-id transferred for identity={}!! aborting..."
                                             .format(id_chl['identity']))
                            self.send_failure(resp_pkt, idf, datapath, in_port)
                            return
                        if d['image-id'] != USERS[id_chl['identity']]['image-id']:
                            self.log.warning("Login for {} failed! Invalid image-Id!".format(id_chl['identity']))
                            self.send_notification(pkt, datapath, in_port,
                                                   "Login for {} failed! Invalid image-Id."
                                                   .format(id_chl['identity']))
                            return
                    allowed_ips = USERS[id_chl['identity']]['allowed_ips']
                else:  # RADIUS user
                    self.log.debug("RADIUS user")
                    allowed_ips, reply_msg = self.get_attr_by_challenge(eap_pkt, id_chl, idf, d)
                    if reply_msg:
                        self.send_notification(pkt, datapath, in_port, reply_msg)
                    if not allowed_ips:
                        self.send_failure(resp_pkt, idf, datapath, in_port)
                        return
                # successfully authenticated, authorize flows
                self.authorize_flows(datapath, id_chl['identity'], d['ip'], allowed_ips)

                # notify supplicant
                resp_pkt.add_protocol(eap.eap(eap_code=eap.EAP_CODE_SUCCESS,
                                              identifier=idf))
                self.log.info2("4: sending SUCCESS to identifier={}".format(idf))
                # cleanup
                del self.identifier_to_identity[eap_pkt.identifier]

            elif eap_pkt.eap_type == eap.EAP_TYPE_NOTIFICATION:
                self.log.info("receiving NOTIFICATION RESPONSE with identifier={} ignoring..."
                              .format(eap_pkt.identifier))
                return
            else:
                self.log.warning("not implemented EAP type: {} aborting...".format(eap_pkt.eap_type))
                return
        # sending response packet
        self.dump_packet(resp_pkt)
        self.send_packet(datapath, in_port, resp_pkt)
        return

    def get_challenge_by_identity(self, identity, eap_pkt, idf):
        """
        handel the RADIUS communication, transmit the IDENTITY and expect a CHALLENGE
        :param identity: supplicant identity
        :param eap_pkt: EAP identity response packet
        :param idf: identifier
        :return: EAP packet with CHALLENGE for the supplicant
        """
        # create radius packet
        attr = {radius.RADIUS_ATTRIBUTE_USER_NAME: identity,
                radius.RADIUS_ATTRIBUTE_EAP_MESSAGE: eap_pkt.serialize(None, None)}
        radius_pkt = radius.radius(radius_code=radius.RADIUS_CODE_ACCESS_REQUEST,
                                   identifier=idf,
                                   secret=RADIUS_SECRET,
                                   attributes=attr)

        # send ACCESS-REQUEST to the RADIUS server and receive the RESPONSE
        self.log.info("1a: forward IDENTITY to RADIUS-Server with identifier={}".format(idf))
        radius_pkt = self.send_receive_radius(radius_pkt)
        if not radius_pkt:
            return None, "ERROR: Connection to the RADIUS-server timed out. Please try again later."

        # handle response
        attr = radius_pkt.attributes
        reply_msg = None
        # display reply msg
        if radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE in attr.keys():
            self.log.warning("REPLY-MESSAGE for identity={}: {}"
                             .format(identity, attr[radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE]))
            reply_msg = attr[radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE]

        # ACCESS-REJECT
        if radius_pkt.radius_code == radius.RADIUS_CODE_ACCESS_REJECT:
            self.log.info("1b: received ACCESS-REJECT from RADIUS-Server with identifier={}"
                          .format(radius_pkt.identifier))
            return None, reply_msg
        # unknown code
        if radius_pkt.radius_code != radius.RADIUS_CODE_ACCESS_CHALLENGE:
            self.log.warning("1b: unknown RADIUS code: {} with identifier={}, aborting..."
                             .format(radius_pkt.radius_code, radius_pkt.identifier))
            return None, reply_msg
        # ACCESS-CHALLENGE
        self.log.info("1b: received ACCESS-CHALLENGE from RADIUS-Server with identifier={}"
                      .format(radius_pkt.identifier))
        # save state
        attr = radius_pkt.attributes
        if radius.RADIUS_ATTRIBUTE_STATE in attr.keys():
            self.log.debug2("save state for idf={} id={}".format(idf, identity))
            self.identifier_to_identity[idf] = \
                {'identity': identity, 'state': attr[radius.RADIUS_ATTRIBUTE_STATE]}
        else:
            self.log.warning("RADIUS-ACCESS-CHALLENGE without STATE attribute (identifier={})!! aborting..."
                             .format(radius_pkt.identifier))
            return None, reply_msg
        # sending challenge request to client
        if radius.RADIUS_ATTRIBUTE_EAP_MESSAGE in attr.keys():
            return eap.eap.parser(attr[radius.RADIUS_ATTRIBUTE_EAP_MESSAGE]), reply_msg
        else:
            self.log.warning("RADIUS-ACCESS-CHALLENGE without EAP-Message attribute (identifier={})!! aborting..."
                             .format(radius_pkt.identifier))
            return None, reply_msg

    def get_attr_by_challenge(self, eap_pkt, id_chl, idf, d):
        """
        perform the RADIUS communication, transfer the CHALLENGE response and expect the authorization attributes
        :param eap_pkt: EAP challenge response packet
        :param id_chl: identifier-to-identity state entry
        :param idf: identifier
        :param d: extra data dict
        :return: allowed ips as list or single string
        """
        # remove data part for the encapsulation
        eap_pkt.length -= len(eap_pkt.data)  # recalculate the length
        eap_pkt.data = None  # clear EAP data part
        # create RADIUS-REQUEST packet
        attr = {radius.RADIUS_ATTRIBUTE_USER_NAME: id_chl['identity'],
                radius.RADIUS_ATTRIBUTE_STATE: id_chl['state'],
                radius.RADIUS_ATTRIBUTE_EAP_MESSAGE: eap_pkt.serialize(None, None)}
        # add additional attributes like docker-image-id
        if 'image-id' in d:
            attr[radius.RADIUS_ATTRIBUTE_VENDOR_SPECIFIC] = \
                {radius.RADIUS_VENDOR_EAPOUDP: {radius.RADIUS_ATTRIBUTE_EAPOUDP_IMAGE_ID: d['image-id']}}
        radius_pkt = radius.radius(radius_code=radius.RADIUS_CODE_ACCESS_REQUEST,
                                   identifier=idf,
                                   secret=RADIUS_SECRET,
                                   attributes=attr)

        # send ACCESS-REQUEST to the RADIUS server and receive the RESPONSE
        self.log.info("3a: forward CHALLENGE response to RADIUS-Server with identifier={}".format(idf))
        radius_pkt = self.send_receive_radius(radius_pkt)
        if not radius_pkt:
            return None, "ERROR: Connection to the RADIUS-server timed out. Please try again later."

        attr = radius_pkt.attributes
        reply_msg = None
        # display reply msg
        if radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE in attr.keys():
            self.log.warning("REPLY-MESSAGE for identity={}: {}"
                             .format(id_chl['identity'], attr[radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE]))
            reply_msg = attr[radius.RADIUS_ATTRIBUTE_REPLY_MESSAGE]
        # handle response
        # ACCESS-REJECT
        if radius_pkt.radius_code == radius.RADIUS_CODE_ACCESS_REJECT:
            self.log.info("3b: received ACCESS-REJECT with identifier={}".format(radius_pkt.identifier))
            return None, reply_msg
        # unknown code
        if radius_pkt.radius_code != radius.RADIUS_CODE_ACCESS_ACCEPT:
            self.log.warning("3b: unknown RADIUS code: {} with identifier={}, aborting..."
                             .format(radius_pkt.radius_code, radius_pkt.identifier))
            return None, reply_msg
        # ACCESS-ACCEPT
        self.log.info("3b: received RADIUS-ACCESS-ACCEPT with identifier={} \o/".format(radius_pkt.identifier))
        # parse radius attributes
        self.log.info("attributes: {}:".format(attr))
        # Vendor-Specific-Attributes (VSA) stored as dict of Vendors, including a dict of Vendors-Attributes
        if radius.RADIUS_ATTRIBUTE_VENDOR_SPECIFIC in attr.keys():
            vendors = attr[radius.RADIUS_ATTRIBUTE_VENDOR_SPECIFIC]
            if radius.RADIUS_VENDOR_EAPOUDP in vendors.keys():
                vendor_attrs = vendors[radius.RADIUS_VENDOR_EAPOUDP]
                if radius.RADIUS_ATTRIBUTE_EAPOUDP_ALLOWED_IPS in vendor_attrs.keys():
                    return vendor_attrs[radius.RADIUS_ATTRIBUTE_EAPOUDP_ALLOWED_IPS].split(","), reply_msg
                else:
                    self.log.warning("no allowed-ips specified for {} with identifier={}!"
                                     .format(id_chl['identity'], radius_pkt.identifier))
            else:
                self.log.warning("no EAPoUDP attributes specified for {} with identifier={}!"
                                 .format(id_chl['identity'], radius_pkt.identifier))
        else:
            self.log.warning("no Vendor-Specific-Attributes specified for {} with identifier={}!"
                             .format(id_chl['identity'], radius_pkt.identifier))
        return None, reply_msg

    def authorize_flows(self, datapath, sup_id, sup_ip, allowed_ips):
        """
        helper function to authorize the flow between supplicant and allowed ips
        :param datapath:
        :param sup_id: supplicant's identity, just for the log
        :param sup_ip: supplicant ip
        :param allowed_ips: list of allowed ips
        :return: nothing
        """
        for allowed_ip in allowed_ips:
            self.install_allow_ipv6_flows(datapath, sup_ip, allowed_ip, REAUTH_TIMEOUT)
        self.log.debug("authorization for identity={} finished.".format(sup_id))

    def send_failure(self, resp_pkt, idf, datapath, in_port):
        """
        helper function to send the failure packet to the supplicant
        :param resp_pkt: basic response packet
        :param idf: identifier
        :param datapath:
        :param in_port:
        :return: nothing
        """
        resp_pkt.add_protocol(eap.eap(eap_code=eap.EAP_CODE_FAILURE,
                                      identifier=idf))
        self.log.info2("X: sending FAILURE with identifier={}".format(idf))
        self.send_packet(datapath, in_port, resp_pkt)

    def send_notification(self, pkt, datapath, in_port, message):
        """
        helper function to send a notification packet to the supplicant
        :param pkt: basic packet
        :param datapath:
        :param in_port:
        :param message: the readable message for the supplicant
        :return: nothing
        """
        resp_pkt = self.generate_response_packet(pkt)
        idf = self.get_new_identifier()
        resp_pkt.add_protocol(eap.eap(eap_code=eap.EAP_CODE_REQUEST,
                                      identifier=idf,
                                      eap_type=eap.EAP_TYPE_NOTIFICATION,
                                      data=message))
        self.log.info2("sending a NOTIFICATION-REQUEST with identifier={}".format(idf))
        self.log.debug2("NOTIFICATION message: {}".format(message))
        self.send_packet(datapath, in_port, resp_pkt)

    def get_new_identifier(self):
        self.identifier = (self.identifier + 1) % 255  # identifier filed is only 1 byte
        return self.identifier

    def send_receive_radius(self, radius_pkt):
        """
        helper function sends and receives RADIUS packets
        :param radius_pkt: RADIUS packet to send
        :return: received RADIUS packet
        """
        self.log.debug2("RADIUS packet dump: {}".format(radius_pkt))
        # create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # open UDP socket
        sock.settimeout(SOCKET_TIMEOUT)
        # send ACCESS-REQUEST to the RADIUS server
        sock.sendto(radius_pkt.serialize(None, None), RADIUS_ADDR)
        try:
            # receive response from RADIUS server
            data, server = sock.recvfrom(BUFFER_SIZE)
        except Exception as err:
            self.log.error("Error in send_receive_radius: {}".format(err))
            return None
        # parse response
        radius_pkt = radius.radius.parser(data)
        self.log.debug2("RADIUS packet dump: {}".format(radius_pkt))
        return radius_pkt

    def generate_response_packet(self, pkt):
        """
        helper function to generate the response packet to the supplicant
        switch the destination und source addresses
        :param pkt: incoming packet
        :return: outgoing packet
        """
        self.log.debug("generating RESPONSE packet")
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        udp_pkt = pkt.get_protocol(udp.udp)

        resp_pkt = packet.Packet()
        resp_pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                                dst=eth_pkt.src,
                                                src=self.my_addr))  # eth_pkt.dst = IPv6mcast_01 (33:33:00:00:00:01)
        resp_pkt.add_protocol(ipv6.ipv6(nxt=ipv6_pkt.nxt,
                                        dst=ipv6_pkt.src,
                                        src=self.my_ip))  # ipv6_pkt.dst = ff02::1
        # src='fe80::e4c6:91ff:feff:6548'))
        resp_pkt.add_protocol(udp.udp(dst_port=udp_pkt.src_port,
                                      src_port=udp_pkt.dst_port))
        return resp_pkt

    def dump_packet(self, pkt):
        """
        helper function to dump all protocols of a packet
        :param pkt: packet to dump
        :return: nothing
        """
        p_str = "packet dump:\n"
        for p in pkt.protocols:
            p_str += "\t" + str(p) + "\n"
        self.log.debug(p_str[:-1])

    @staticmethod
    def parse_extra_data(data):
        """
        helper function to parse extra data, e.g. supplicant ip or allowed ips
        :param data: data string: name=value,name=value1;value2,name=...
        :return: dict with names as keys and values as strings or lists
        """
        d = {}
        for attr in data.split(','):
            name, value = attr.split('=')
            d[name] = value.split(";") if ";" in value else value
        return d
