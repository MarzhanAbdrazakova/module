import json
import logging
import os
import requests

from ryu.app import simple_switch_13
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.lib.ofctl_v1_3 import mod_flow_entry
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib.packet import packet
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_utils

simple_switch_instance_name = 'restswitch'
rules_default = 'channels.json'
rules = 'channels.json'


class ForwardRest(simple_switch_13.SimpleSwitch13):

    _CONTEXTS = { 'dpset': dpset.DPSet,
                  'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(ForwardRest, self).__init__(*args, **kwargs)
        self.switches = {}
        dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.data = {}
        self.waiters = {}
        self.data['dpset'] = dpset
        self.data['waiters'] = {}
        
        wsgi.register(ForwardController, {simple_switch_instance_name : self})
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=100, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    
class ForwardController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ForwardController, self).__init__(req, link, data, **config)
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)
        self.simpl_switch_spp = data[simple_switch_instance_name]
        self.dpset = self.simpl_switch_spp.data['dpset']
        
        try:
            jsondict = json.load(open(rules))
            self.logger.info("JSON configuration loaded from %s:" % rules)
        except IOError:
            try:
                jsondict = json.load(open(rules_default))
                self.logger.info("JSON configuration loaded from %s:" % rules_default)
            except IOError:
                self.logger.info("Can't open %s and %s" % (rules,rules_default))
                self.dst = {}
                self.channels = {}
        try:
            self.dst = jsondict["dst"]
            self.channels = jsondict["channels"]
            self.logger.info(json.dumps(jsondict))
        except ValueError:
            self.logger.info("JSON syntaxis error in %s" % rules)
            self.dst = {}
            self.channels = {}
        self.r = []
    
    def delete_flow(self, dp, flows):
        if flows == "":
            return
        cmd = dp.ofproto.OFPFC_DELETE_STRICT 
        for f in flows:
            flow = f
            mod_flow_entry(dp, flow, cmd)
        self.r = []   

    def set_flows(self, dp, f): 

        flow = {"priority":1000,
                "match":{"eth_type": 2048, "ip_proto": 6,"in_port": int(f["iport"]), "ipv4_dst":self.dst['nw'],"tcp_dst":self.dst['tp']},
                "actions":[{"type":"SET_FIELD", "field": "ipv4_dst", "value":f["nw"]},
                           {"type":"SET_FIELD", "field": "tcp_dst", "value": int(f["tp"])},
                           {"type":"SET_FIELD", "field": "eth_dst", "value":f["dl"]},
                           {"type":"OUTPUT", "port": int(f["oport"])}]}
        try:
            mod_flow_entry(dp, flow, dp.ofproto.OFPFC_ADD)
        except:
            raise ValueError('Invalid rule parameter.')
        self.r.append(flow)
        
        flow = {"priority":1000,
                "match":{"eth_type": 2048, "ip_proto": 6,"in_port": int(f["oport"]),"ipv4_src":f["nw"],"tcp_src":f["tp"]},
                "actions":[{"type":"SET_FIELD", "field": "ipv4_src", "value":self.dst['nw']}, 
                           {"type":"SET_FIELD", "field": "tcp_src", "value": int(self.dst['tp'])}, 
                           {"type":"SET_FIELD", "field": "eth_src", "value":self.dst["dl"]}, 
                           {"type":"OUTPUT", "port": int(f["iport"])}]}
        try:
            mod_flow_entry(dp, flow, dp.ofproto.OFPFC_ADD)
        except:
            raise ValueError('Invalid rule parameter.')
        self.r.append(flow)
        self.delete_flow(dp,self.r)

    @route('rules', '/rules', methods=['GET'])
    def get_conf_handler(self, req, **kwargs):

        body = json.dumps({'dst': self.dst,
                           'channels': self.channels})

        return Response(content_type='application/json', body=body)

    @route('rules', '/rules', methods=['POST'])
    def set_conf_handler(self, req, **kwargs):
        body = json.dumps({'dst': self.dst,
                           'channels': self.channels})

        jsondict = json.loads(req.body)
        self.dst = jsondict["dst"]
        self.channels = jsondict["channels"]

        f = open(rules, "w+")
        f.write(json.dumps({'dst': self.dst,
                            'channels': self.channels}))
        f.close()
        return Response(content_type='application/json', body=body)


    @route('channel', '/channel/{channel}', methods=['GET'], requirements={'channel': r'[0-9]'})
    def get_handler(self, req, **kwargs):

        channel = kwargs['channel']
        c = self.channels[channel]
        dp = self.dpset.get(c['dpid'])
        self.set_flows(dp, c) 

        body = json.dumps({'channel': channel,  'result': c})

        return Response(content_type='application/json', body=body)
