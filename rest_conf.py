import json
import logging
import os
import requests
import re


from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser


rules_default = 'channels.json'
rules = 'channels.json'
LOG = logging.getLogger(__name__)

class ForwardRest(app_manager.RyuApp):

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
        self.data['waiters'] = self.waiters
        ForwardController.set_logger(self.logger)
        wsgi.registory['ForwardController'] = self.data
        wsgi.register(ForwardController, self.data)


    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            ForwardController.regist_ofs(ev.dp)
        else:
            ForwardController.unregist_ofs(ev.dp)

class ForwardOfsList(dict):
    def __init__(self):
        super(ForwardOfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('forwarding sw is not connected.')

        dps = {}

        try:
            dpid = dpid_lib.str_to_dpid(dp_id)
        except:
            raise ValueError('Invalid switchID.')

        if dpid in self:
            dps = {dpid: self[dpid]}
        else:
            msg = 'forwarding sw is not connected. : switchID=%s' % dp_id
            raise ValueError(msg)

        return dps

class ForwardController(ControllerBase):

    _OFS_LIST = ForwardOfsList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(ForwardController, self).__init__(req, link, data, **config)
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

        try:
            jsondict = json.load(open(rules))
            self.logger.info("JSON configuration loaded from %s:" % rules)
        except IOError:
            try:
                jsondict = json.load(open(rules_default))
                self.logger.info("JSON configuration loaded from %s:" % rules_default)
            except IOError:
                self.logger.info("Can't open %s and %s" % (rules,rules_default))
                self.ovs = {}
                self.channels = {}
        try:
            self.ovs = jsondict["ovs"]
            self.channels = jsondict["channels"]
            self.logger.info(json.dumps(jsondict))
        except ValueError:
            self.logger.info("JSON syntaxis error in %s" % rules)
            self.ovs = {}
            self.channels = {}

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[FW][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp):
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = Forward(dp)
        except OFPUnknownVersion as message:
            ForwardController._LOGGER.info('dpid=%s: %s',
                                            dpid_str, message)
            return

        ForwardController._OFS_LIST.setdefault(dp.id, f_ofs)
        ForwardController._LOGGER.info('dpid=%s: Forwarding module is joined.',
                                        dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in ForwardController._OFS_LIST:
            del ForwardController._OFS_LIST[dp.id]
            ForwardController._LOGGER.info('dpid=%s: Forwarding module is disconnected.',
                                            dpid_lib.dpid_to_str(dp.id))


    @route('activate', '/activate', methods = ['GET'])
    def activ_rules(self, req, **kwargs):
        mode = 'add'
        for c in self.channels.values():
            if c["active"] == "1":
                f = self.set_data(c,mode)

        body = json.dumps({'result': 'Rules are activated.'})
        return Response(content_type='application/json', body=body)
    
    @route('channel', '/channel/all', methods = ['GET'])
    def get_channels(self, req, **kwargs):
        body = json.dumps({'channels': self.channels})
        return Response(content_type='application/json', body=body)

    @route('ovs', '/ovs/all', methods = ['GET'])
    def get_ovs(self, req, **kwargs):
        body = json.dumps({'ovs': self.ovs})
        return Response(content_type='application/json', body=body)

    @route('channel', '/channel', methods = ['POST'])
    def set_channel(self, req, **kwargs):
        jsonconf = json.loads(req.body)

        for l in jsonconf.keys():
            ch = l
        for k, v in self.channels.items():
            if k == ch:
                c = self.channels[ch]
                mode = 'delete'
                self.set_data(c, mode)
        self.channels[ch] = jsonconf[ch]

        f = open(rules, "w+")
        f.write(json.dumps({"ovs": self.ovs, "channels": self.channels}))
        f.close()
        mode = 'add'
        c = self.channels[ch]
        self.set_data(c,mode)
        body = json.dumps({'id':ch, 'result': 'Configurations are added.'})
        return Response(content_type='application/json', body=body)


    @route('ovs', '/ovs', methods = ['POST'])
    def set_ovs(self, req, **kwargs):
        jsonconf = json.loads(req.body)
        self.ovs.update(jsonconf)

        f = open(rules, "w+")
        f.write(json.dumps({"ovs": self.ovs, "channels": self.channels}))
        f.close()
        body = json.dumps({'result': 'OVS updated.'})
        return Response(content_type='application/json', body=body)


    @route('channel', '/channel/{channel}/{active}', methods = ['GET'], requirements={'channel': r'[0-9]', 'active': r'[0-1]'})
    def get_channel(self, req, **kwargs):
        ch = kwargs['channel']
        active = kwargs['active']
        mode = 'delete'
        try:
            c = self.channels[ch]
        except KeyError:
            message = "channel doesn't exists"
            return Response(status=400, body=str(message))
            
        self.set_data(c, mode)
        if active == "0":
            self.channels[ch]["active"] = "0"
        else:
            self.channels[ch]["active"] = "1"
            mode = 'add'
            self.set_data(c, mode)
        f = open(rules, "w+")
        f.write(json.dumps({"ovs": self.ovs, "channels": self.channels}))
        f.close()

        body = json.dumps({ 'id': ch, 'result': 'Success' })
        return Response(content_type='application/json', body=body)



    def set_data(self, c,mode):
        ip_src = c["src"]["ip"]
        ip_dst = c["dst"]["ip"]
        vlan_src = int(c["src"]["vlan"])
        vlan_dst = int(c["dst"]["vlan"])
        ovs = str(c["dst"]["ovs"])
        dp1 = self.ovs[ovs]["dpid"]
        inport1 = int(c["dst"]["iport"])
        outport1 = int(c["dst"]["oport"])     
        tcp1 = int(c["src"]["tp"])
        tcp2 = int(c["dst"]["tp"])
        
        f = self._set_rule(dp1, ip_src, ip_dst,vlan_src,vlan_dst, inport1, outport1, mode)

        f = self._set_rule(dp1,  ip_dst, ip_src,vlan_dst, vlan_src, outport1, inport1, mode)

        dps = self._OFS_LIST.get_ofs(dp1)

        for f_ofs in dps.values():
            try:
                flow = f_ofs.set_tcp_port(ip_src, ip_dst, tcp1, tcp2,vlan_src,vlan_dst, inport1, outport1, mode)
            except ValueError as message:
                return Response(status=400, body=str(message))
        return f


    def _set_rule(self, dp, ip_src, ip_dst, vlan_src,vlan_dst, inport, outport, mode):

        try:
            dps = self._OFS_LIST.get_ofs(dp) #returns dict {switchid : Forward(switchid)}
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                flow = f_ofs.set_rule(ip_src, ip_dst, vlan_src,vlan_dst, inport, outport, mode)

            except ValueError as message:
                return Response(status=400, body=str(message))

        return flow


class Forward(object):

    _OFCTL = {ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp):
        super(Forward, self).__init__()
        self.dp = dp
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    def set_tcp_port(self, ip_src, ip_dst,tcp1, tcp2, vlan_src, vlan_dst, inport, outport, mode):
        flows = []
        if mode == 'add':
            cmd = self.dp.ofproto.OFPFC_ADD
        elif mode == 'delete':
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
        
        match = {"in_port":inport, "dl_vlan": int(vlan_src),"ip_proto": 6,"tcp_dst": int(tcp1),  "ipv4_src":ip_src, 
                 "ipv4_dst": ip_dst, "eth_type": 2048}
        actions = [ {"type": "POP_VLAN", "ethertype": 33024}, {"type": "PUSH_VLAN", "ethertype": 33024},
                    {"type":"SET_FIELD", "field": "vlan_vid", "value": 4096+int(vlan_dst)},
                    {"type":"SET_FIELD", "field": "tcp_dst", "value": int(tcp2)},
                    {"type":"OUTPUT", "port": outport}]

        flow = self._to_of_flow(priority=1000,
                                match=match, actions=actions)
        flows.append(flow)

        try:
            ofctl_v1_3.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        match = {"in_port":outport, "dl_vlan": int(vlan_dst), "ipv4_src":ip_dst, "ip_proto": 6,"tcp_src": int(tcp2), 
                 "ipv4_dst": ip_src, "eth_type": 2048}
        actions = [ {"type": "POP_VLAN", "ethertype": 33024}, {"type": "PUSH_VLAN", "ethertype": 33024},
                    {"type":"SET_FIELD", "field": "vlan_vid", "value": 4096+int(vlan_src)},
                    {"type":"SET_FIELD", "field": "tcp_src", "value": int(tcp1)},
                    {"type":"OUTPUT", "port": inport}]

        flow = self._to_of_flow(priority=1000,
                                match=match, actions=actions)
        flows.append(flow)

        try:
            ofctl_v1_3.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        msg = json.dumps({'result':'Rules added!'})
        return Response(content_type='application/json', body=msg)


    def set_rule(self, ip_src, ip_dst, vlan_src, vlan_dst, inport, outport, mode):
        flows = []
        if mode == 'add':
            cmd = self.dp.ofproto.OFPFC_ADD
        elif mode == 'delete':
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT

        match = {"in_port": inport, "dl_vlan": int(vlan_src), "arp_spa": ip_src,
                 "arp_tpa": ip_dst, "eth_type": 2054}
        actions = [ {"type": "POP_VLAN", "ethertype": 33024}, {"type": "PUSH_VLAN", "ethertype": 33024},
                    {"type":"SET_FIELD", "field": "vlan_vid", "value": 4096+int(vlan_dst)},
                    {"type":"OUTPUT", "port": outport}]

        flow = self._to_of_flow(priority=1000,
                                match=match, actions=actions)
        flows.append(flow)
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        match = {"in_port": outport, "dl_vlan": int(vlan_src), "ipv4_dst": ip_src,
                 "ipv4_src": ip_dst, "eth_type": 2048}
        actions = [{"type":"OUTPUT", "port": inport}]

        flow = self._to_of_flow(priority=1000,
                                match=match, actions=actions)
        flows.append(flow)
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        match = {"in_port": outport, "dl_vlan": int(vlan_src), "arp_tpa": ip_src,
                 "arp_spa": ip_dst, "eth_type": 2054}
        actions = [{"type":"OUTPUT", "port": inport}]

        flow = self._to_of_flow(priority=1000,
                                match=match, actions=actions)
        flows.append(flow)
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        msg = {'result': 'success'}
        return msg


    def _to_of_flow(self, priority, match, actions):
        flow = {'cookie': 0,
                'priority': priority,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'match': match,
                'actions': actions}
        return flow
