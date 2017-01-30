# -*- coding: utf8 -*-
__author__ = 'remy'

from ryu.base import app_manager
import logging
import requests
import time, datetime
import json
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmpv6


from oslo_config import cfg
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
LOG = logging.getLogger('ryu.app.ICMPv6_ND_proxy')


class ICMPV6_proxy(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ICMPV6_proxy, self).__init__(*args, **kwargs)
        self.resolve_table = {}
        self.online_avaliable = True
        if self.load_config() is True:
            # Test servers defined
            self.datetime = None
            server = ""
            try:
                server = self.CONF.stateful.server.translate(None, '\'\"[]')
                requests.get(server)
                self.server = server
            except requests.ConnectionError:
                LOG.warning("Server " + server + " not reachable, ignoring url defined\n" +
                            "The ndp proxy app will resolve the ND solicitations by flooding on the data plane !")
                self.online_avaliable = False
            LOG.debug("Server verification complete")

            # Création thread routine flush
            self.timer = hub.spawn(self.timer_job)

    def load_config(self):
        # Extract config file
        try:
            self.CONF.register_group(cfg.OptGroup(name='icmpv6_nd_proxy',
                                                  title='ICMPv6 ND Proxy options'))
            self.CONF.register_opts([
                cfg.StrOpt('server'),
                cfg.IntOpt('flush_timer'),
                cfg.BoolOpt('enable')
            ], 'icmpv6_nd_proxy')
            if self.CONF.icmpv6_nd_proxy.enable is False:
                LOG.warn("Application ICMPv6 ND proxy désactivé")
                self.stop()
                return False
        except cfg.NoSuchOptError:
            LOG.error("Fichier de configuration invalide")
            self.stop()
            return False

    def timer_job(self):
        timer = self.CONF.icmpv6_nd_proxy.flush_timer
        while True:
            time.sleep(timer)
            # flush table without individual timing reference
            self.resolve_table = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _event_switch_hello_handler(self, ev):
        LOG.info("Le switch n° "+str(ev.datapath.id)+" a changé de statut.")
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = parser.OFPMatch(eth_type=0x86dd,ip_proto=58)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 65535, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=5, hard_timeout=15,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        # check if pkt is an icmpv6 message
        if self.packetIsICMPv6NS(msg):
            if self.online_avaliable is True:
                if self.resolveICMPv6NS_online(msg) is False:
                    self.resolveICMPv6NS_legacy(msg, datapath)
                self.resolveICMPv6NS_legacy(msg, datapath)

        elif self.packetIsICMPv6NA(msg):
            self.resolveICMPv6NA(msg)
        else:
            return None

    def packetIsICMPv6NS(self, message):
        pkt = packet.Packet(message.data)
        icmp6 = pkt.get_protocol(icmpv6.icmpv6)
        if icmp6 is not None:
            if icmp6.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                return True
            return False
        return False

    def packetIsICMPv6NA(self, message):
        pkt = packet.Packet(message.data)
        icmp6 = pkt.get_protocol(icmpv6.icmpv6)
        if icmp6 is not None:
            if icmp6.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
                return True
            return False
        return False

    def resolveICMPv6NS_legacy(self, message, datapath):
        pkt = packet.Packet(message.data)
        icmp6 = pkt.get_protocol(icmpv6.icmpv6)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if icmp6.target in self.resolve_table.keys():
            # forge answer
            type_ = icmp6.ND_NEIGHBOR_ADVERT
            icmpv6_dst_ip = icmp6.data.src
            icmpv6_src_ip = icmp6.target
            actions = [parser.OFPActionOutput(message.in_port)]
            ICMP_Reply = packet.Packet()

            ICMP_Reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=src,
                src=self.resolve_table[icmp6.target]))
            ICMP_Reply.add_protocol(ipv6.ipv6(dst=icmpv6_dst_ip, src=icmpv6_src_ip))
            ICMP_Reply.add_protocol(icmpv6.icmpv6(type_=type_, code=0, data=icmp6.data))

            ICMP_Reply.serialize()

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=ICMP_Reply.data)
            datapath.send_msg(out)
            pass
        else:
            # flood NS package on all ports (for now)
            type_ = icmp6.type_
            icmpv6_dst_ip = icmp6.data.dst
            icmpv6_src_ip = icmp6.data.option
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            ICMP_Reply = packet.Packet()

            ICMP_Reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=dst,
                src=src))
            ICMP_Reply.add_protocol(ipv6.ipv6(dst=icmpv6_dst_ip, src=icmpv6_src_ip))
            ICMP_Reply.add_protocol(icmpv6.icmpv6(type_=type_, code=0, data=icmp6.data))

            ICMP_Reply.serialize()

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=ICMP_Reply.data)
            datapath.send_msg(out)
            pass

    def resolveICMPv6NS_online(self, message):
        # TODO coding online side on TouSIX-Manager before...
        return None

    def resolveICMPv6NA(self, message):
        pkt = packet.Packet(message.data)
        icmp6 = pkt.get_protocol(icmpv6.icmpv6)
        pkt = packet.Packet(message.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        if src not in self.resolve_table.values():
            self.resolve_table[icmp6.target] = src
        # drop package (no action taken after packet_in event)

