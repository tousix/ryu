import logging

import json


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3

LOG = logging.getLogger('ryu.app.restful_ctrl')

class RestfulCTRL(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(RestfulCTRL, self).__init__(*args, **kwargs)

    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def _event_switch_hello_handler(self, ev):
        if ev.enter is True:
            datapath = ev.dp
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
    def _event_switch_hell_handler(self, ev):
        dp = ev.msg.datapath
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
        flows = {str(dp.id): flows}
        print json.dumps(flows)