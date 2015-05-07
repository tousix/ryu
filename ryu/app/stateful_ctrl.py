# -*- coding: utf8 -*-

import logging

import json
import io
import sys

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import ofctl_v1_3
from oslo_config import cfg

LOG = logging.getLogger('ryu.app.stateful_ctrl')


class StatefulCTRL(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(StatefulCTRL, self).__init__(*args, **kwargs)
        # Test ouverture fichier
        try:
            self.CONF.register_group(cfg.OptGroup(name='stateful',
                                     title='Stateful controller options'))
            self.CONF.register_opts([
                                    cfg.StrOpt('filepath'),
                                    cfg.BoolOpt('enable')
                                    ], 'stateful')

            if self.CONF.stateful.enable is False:
                print "Application Contrôleur stateful désactivé"
                sys.exit(0)
            self.filepath = self.CONF.stateful.filepath
            file_test = io.open(self.filepath, mode='r')
            file_test.close()
        except AttributeError:
            print "Erreur : Chemin de fichier invalide"
            sys.exit(0)
        except cfg.NoSuchOptError:
            print "Erreur : Fichier de configuration invalide"
            sys.exit(0)

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _event_switch_hello_handler(self, ev):
        print "Le switch n° "+str(ev.datapath.id)+" a changé de statut."
        datapath = ev.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _event_switch_connection_handler(self, ev):
        dp = ev.msg.datapath
        count = 0
        flows = []
        for stats in ev.msg.body:
            actions = ofctl_v1_3.actions_to_str(stats.instructions)
            match = ofctl_v1_3.match_to_str(stats.match)

            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'actions': actions,
                 'match': match,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'packet_count': stats.packet_count,
                 'table_id': stats.table_id,
                 'length': stats.length,
                 'flags': stats.flags}
            flows.append(s)
            count += 1
        flows = {str(dp.id): flows}
        # print json.dumps(flows)
        # print count

        deseria = DeserializeJSON()

        rules = list()
        if deseria.verify_instuctions(self.filepath, dp.id, count, rules) is False:
            print "Nombre de règles sur "+str(dp.id)+" différent du fichier de configuration"
            self._restore_rules(self, dp, rules)
        else:
            print "Pas de modification à apporter sur le switch n° "+str(dp.id)

    @staticmethod
    def _restore_rules(self, dp, rules):
        print "Restauration des règles de "+str(dp.id)+" en cours..."

        for rule in rules:
            # Separation des regles flux / groupes
            if ("buckets" in rule) is True:
                ofctl_v1_3.mod_group_entry(dp, rule, dp.ofproto.OFPGC_ADD)
            else:
                ofctl_v1_3.mod_flow_entry(dp, rule, dp.ofproto.OFPFC_ADD)
        print "Restauration des règles de "+str(dp.id)+" terminé"


class DeserializeJSON():

    def __init__(self, *args, **kwargs):
        self.modeio = "rt"

    def _open_file(self, filepath):
        self.file_test = io.open(filepath, mode=self.modeio)

    def _clean_file(self):
        self.instruction = list()
        for line in self.file_test:
            try:
                self.instruction.append(json.loads(line))
            except ValueError:
                continue

    def verify_instuctions(self, filepath, dpid, number, rules):
        self._open_file(filepath)
        self._clean_file()
        count = 0

        for rule in self.instruction:
            if rule['dpid'] == dpid or rule['dpid'] == str(dpid):
                if ("buckets" in rule) is False:
                    count += 1
                rules.append(rule)
        if count == number:
            return True
        else:
            return False

    def _close_file(self):
        self.file_test.close()