import json
import logging
import os
import requests
import re

from ryu.app import simple_switch_13
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib.mac import haddr_to_bin
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.lib.packet import packet
from ryu.lib import ofctl_utils, mac
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.ofproto import ether, inet
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser


REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'


VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32

simple_switch_instance_name = 'restswitch'
rules_default = 'channels.json'
rules = 'channels.json'
LOG = logging.getLogger(__name__)

class ForwardRest(simple_switch_13.SimpleSwitch13, app_manager.RyuApp):

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
 
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            ForwardController.regist_ofs(ev.dp)
        else:
            ForwardController.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        ForwardController.packet_in_handler(ev.msg)
 
class ForwardOfsList(dict):
    def __init__(self):
        super(ForwardOfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('forwarding sw is not connected.')

        dps = {}
        if dp_id == 'all':
            dps = self
        else:
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
        self.simpl_switch_spp = data[simple_switch_instance_name]
        self.dpset = self.simpl_switch_spp.data['dpset']
        self.waiters = self.simpl_switch_spp.data['waiters']
        
        try:
            jsondict = json.load(open(rules))
            self.logger.info("JSON configuration loaded from %s:" % rules)
        except IOError:
            try:
                jsondict = json.load(open(qconf_default))
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

    #GET all imported rules  
    @route('conf', '/conf', methods = ['GET'])
    def get_conf_handler(self, req, **kwargs):

        body = json.dumps({'dst': self.dst,
                           'channels': self.channels})

        return Response(content_type='application/json', body=body)

    #POST new rule and write it into qconf file
    @route('conf', '/conf', methods = ['POST'])
    def set_conf_handler(self, req, **kwargs):
        body = json.dumps({'dst': self.dst,
                           'channels': self.channels})

        jsondict = json.loads(req.body)
        self.dst = jsondict["dst"]
        self.channels = jsondict["channels"]

        f = open(qconf, "w+")
        f.write(json.dumps({'dst': self.dst,
                            'channels': self.channels}))
        f.close()
        return Response(content_type='application/json', body=body)


    @route('channel', '/channel/{channel}/{status}', methods = ['GET'], requirements={'channel': r'[0-9]'})
    def get_channel(self, req, **kwargs):
        ch = kwargs['channel']
        st = kwargs['status']
        flows = self.channels[ch]
        dp = flows["dpid"]
   
        if st == "0": 
            flow = flows["transp"]
            
            self._set_rule(flow, dp)
        elif st == "1":
            flow = flows["scrypt"]
            self._set_rule(flow, dp)
        elif st =="2":
            flow = flows["qcrypt"]
            self._set_rule(flow, dp)     
        elif st == 5:
            flow = os.system(qpath + '/bin/crypto_stat eth1 eth2')
        elif st == 6:
            p = os.popen(qpath + '/bin/crypto_stat_get eth1 eth2')
            flow = p.readlines() 

        body = json.dumps({'channel': ch, 'status': st, 'result': flow})
        
        return Response(content_type='application/json', body=body)

    
    def _set_rule(self, req, switchid):
        
        if "vlan_id" in req.keys():
            vid = req["vlan_id"]
        else:
            vid = VLANID_NONE 
        try:
            dps = self._OFS_LIST.get_ofs(switchid) #returns dict {switchid : Forward(switchid)}
            #vid = ForwardController._conv_toint_vlanid(vlan_id) 
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_rule(self.dst,req, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)
     

    @route('qkey', '/qkey/{channel}', methods=['POST'], requirements={'channel': r'[0-9]'})
    def post_handler(self, req, **kwargs):

        # In JSON file channel number is the key (string)
        channel = kwargs['channel']
        c = self.channels[channel]
        #dp = self.dpset.get(c['dpid'])

        qkey = req.body
        addr = req.remote_addr
        
        body = json.dumps({'channel': channel,
                           'qkey': qkey,
                           'addr': addr})

        body = "ADDR: %s QKEY: %s\n" % (addr, qkey)

        self.logger.info("body: " + body)
        for url in c["qcrypt"]["key_poins"]:
            body += "URL %s RESULT:\n" % url
            try:
                r = requests.post(url, qkey)
                body += r.text
            except: #requests.ConnectionError:
                body += "URL %s: can't connect\n" % url
        return Response(content_type='application/json', body=body)


    @route('forward', '/forward/{dpid}', methods = ['GET'])
    def get_rules(self, req, **kwargs):
        dp = kwargs['dpid']
        result = self._get_rules(dp)
        return result
        
    @route('forward', '/forward/{dpid}/{vlan_id}', methods = ['GET'])
    def get_vrules(self, req, **kwargs):
        dp = kwargs['dpid']
        vlan_id = kwargs['vlan_id']
        result = self._get_rules(dp, vlan_id)
        return result

       
    def _get_rules(self, dp, vid = VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(dp)
            #vid = ForwardController._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))
        msgs = []
        for f_ofs in dps.values():
            rules = f_ofs.get_rules(self.waiters, vid)
            msgs.append(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)    

    @route('forward', '/forward/{dpid}/{rule_id}', methods = ['DELETE'])
    def delete_rule(self, req, **kwargs):
        dp = kwargs['dpid']  
        rid = kwargs['rule_id']      
        result = self._delete_rule(dp,rid)
        return result

    @route('forward', '/forward/{dpid}/{rule_id}/{vlan_id}', methods = ['DELETE'])
    def delete_vrule(self, req, **kwargs):
        dp = kwargs['dpid']
        rid = kwargs['rule_id']
        vlan_id = kwargs['vlan_id']
        result = self._delete_rule(dp,rid, vlan_id)
        return result

    def _delete_rule(self, dp,rid, vid = VLANID_NONE):        
        try:        
            dps =  self._OFS_LIST.get_ofs(dp)
            #vid = ForwardController._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.delete_rule(rid, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body) 

    @staticmethod
    def packet_in_handler(msg):
        pkt = packet.Packet(msg.data)
        dpid_str = dpid_lib.dpid_to_str(msg.datapath.id)

class Forward(object):
    
    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp):
        super(Forward, self).__init__()
        self.vlan_list = {}
        self.vlan_list[VLANID_NONE] = 0  # for VLAN=None
        self.dp = dp
        version = dp.ofproto.OFP_VERSION
         
        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]
        self.r = [] 

    def _update_vlan_list(self, vlan_list): 
        for vlan_id in self.vlan_list.keys():
            if vlan_id is not VLANID_NONE and vlan_id not in vlan_list:
                del self.vlan_list[vlan_id]

    def _get_cookie(self, vlan_id):
        if vlan_id != VLANID_NONE:
            vlan_id = int(vlan_id, 0)
        if vlan_id == 'all':
            vlan_ids = self.vlan_list.keys()
        else:
            vlan_ids = [vlan_id]

        cookie_list = []
        for vlan_id in vlan_ids:
            self.vlan_list.setdefault(vlan_id, 0)
            self.vlan_list[vlan_id] += 1
            self.vlan_list[vlan_id] &= ofproto_v1_3_parser.UINT32_MAX
            cookie = (vlan_id << COOKIE_SHIFT_VLANID) + \
                self.vlan_list[vlan_id]
            cookie_list.append([cookie, vlan_id])

        return cookie_list

    @staticmethod
    def _cookie_to_ruleid(cookie): #converts cookie into rule_id value
        return cookie & ofproto_v1_3_parser.UINT32_MAX

    # REST command template
    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {'switch_id': switch_id,
                    key: value}
        return _rest_command
     
    @rest_command
    def set_rule(self, dst, rest, waiters, vid):
        msgs = []
        cookie_list = self._get_cookie(vid)
        for cookie, vid in cookie_list:
            msg = self._set_rule(cookie, dst, rest, waiters, vid)
            msgs.append(msg)
        return 'command_result', msgs

    
    def _set_rule(self, cookie, dst, f, waiters, vlan_id): 
        msgs = []
        self.delete_flow(self.r) #deletes previous rules
        
        match = {"eth_type": 2048, "ip_proto": 6, "in_port": int(f["iport"]), "ipv4_dst":dst["nw"],"tcp_dst":dst["tp"]}
        actions = [{"type":"SET_FIELD", "field": "ipv4_dst", "value":f["nw"]},
                   {"type":"SET_FIELD", "field": "tcp_dst", "value": int(f["tp"])},
                   {"type":"SET_FIELD", "field": "eth_dst", "value":f["dl"]},
                   {"type":"OUTPUT", "port": int(f["oport"])}]
        if "vlan_id" in dst.keys():
            match["dl_vlan"]=f["vlan_id"]
        flow = self._to_of_flow(cookie=cookie, priority=1000,
                                match=match, actions=actions) 
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, self.dp.ofproto.OFPFC_ADD)
        except:
            raise ValueError('Invalid rule parameter.')        
        self.r.append(flow) 
      
        match = {"eth_type": 2048, "ip_proto": 6, "in_port": int(f["oport"]),"ipv4_src":f["nw"],"tcp_src":f["tp"]}
        actions = [{"type":"SET_FIELD", "field": "ipv4_src", "value":dst["nw"]}, 
                   {"type":"SET_FIELD", "field": "tcp_src", "value": int(dst["tp"])}, 
                   {"type":"SET_FIELD", "field": "eth_src", "value":dst["dl"]}, 
                   {"type":"OUTPUT", "port": int(f["iport"])}]
        if "vlan_id" in f.keys():
            match["dl_vlan"]=f["vlan_id"]
        flow = self._to_of_flow(cookie=cookie, priority=1000,
                                match=match, actions=actions) 
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, self.dp.ofproto.OFPFC_ADD)
        except:
            raise ValueError('Invalid rule parameter.')
        self.r.append(flow) 

        rule_id = Forward._cookie_to_ruleid(cookie)
        msg = {'result': 'success',
               'details': 'Rule added. : rule_id=%d' % rule_id}
        
        if vlan_id != VLANID_NONE:
            msg.setdefault('vlan_id', vlan_id)
        
        return msg

    def delete_flow(self,flows):
        if flows == "":
            return
        cmd = self.dp.ofproto.OFPFC_DELETE_STRICT 
        for f in flows:
            flow = f
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        self.r = []   

    @rest_command
    def get_rules(self, waiters, vlan_id):
        
        rules = {}
        msgs = self.ofctl.get_flow_stats(self.dp, waiters) 
 
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                priority = flow_stat['priority']
                vid = flow_stat['match'].get('dl_vlan', VLANID_NONE)
                if vlan_id == 'all' or vlan_id == vid:
                    rule = self._to_rest_rule(flow_stat)
                    rules.setdefault(vid, [])
                    rules[vid].append(rule)
        
        get_data = []
        for vid, rule in rules.items():
            if vid == VLANID_NONE:
                vid_data = {'rules': rule}
            else:
                vid_data = {'vlan_id': vid, 'rules': rule}
            get_data.append(vid_data)
       
        return 'command_result', get_data

    @rest_command
    def delete_rule(self, rid, waiters, vlan_id): #removes rule by rule_id from table
        try:
            if rid == 'all':
                rule_id = 'all'
            else:
                rule_id = int(rid)
        except:
            raise ValueError('Invalid ruleID.')

        vlan_list = []
        delete_list = []

        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                cookie = flow_stat['cookie']
                ruleid = Forward._cookie_to_ruleid(cookie)
                priority = flow_stat['priority']
                dl_vlan = flow_stat['match'].get('dl_vlan', VLANID_NONE)
                if ((rule_id == 'all' or rule_id == ruleid) and
                    (vlan_id == dl_vlan or vlan_id == 'all')):
                    match = Match.to_mod_openflow(flow_stat['match'])
                    delete_list.append([cookie, priority, match])
                else:
                    if dl_vlan not in vlan_list:
                        vlan_list.append(dl_vlan)

        self._update_vlan_list(vlan_list) 

        if len(delete_list) == 0:
            msg_details = 'Rule is not exist.'
            if rule_id != 'all':
                msg_details += ' : ruleID=%d' % rule_id
            msg = {'result': 'failure',
                   'details': msg_details}
        else:
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
            actions = []
            delete_ids = {}
            for cookie, priority, match in delete_list:
                flow = self._to_of_flow(cookie=cookie, priority=priority,
                                        match=match, actions=actions)
                self.ofctl.mod_flow_entry(self.dp, flow, cmd)

                vid = match.get('dl_vlan', VLANID_NONE)
                rule_id = Forward._cookie_to_ruleid(cookie)
                delete_ids.setdefault(vid, '')
                delete_ids[vid] += (('%d' if delete_ids[vid] == ''
                                     else ',%d') % rule_id)

            msg = []
            for vid, rule_ids in delete_ids.items():
                del_msg = {'result': 'success',
                           'details': 'Rule deleted. : ruleID=%s' % rule_ids}
                if vid != VLANID_NONE:
                    del_msg.setdefault('vlan_id', vid)
                msg.append(del_msg)

        return 'command_result', msg


    def _to_of_flow(self, cookie, priority, match, actions):
        flow = {'cookie': cookie,
                'priority': priority,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'match': match,
                'actions': actions}
        return flow

    def _to_rest_rule(self, flow):
        ruleid = Forward._cookie_to_ruleid(flow['cookie'])
        rule = {'rule_id': ruleid}
        rule.update({'priority': flow['priority']})
        rule.update({'match':Match.to_rest(flow)})
        #rule.update({'match':flow["match"]})
        rule.update(Action.to_rest(flow))
        #rule.update({'actions':flow["actions"]})
        return rule

class Match(object):

    _CONVERT = {REST_DL_TYPE:
                {REST_DL_TYPE_ARP: ether.ETH_TYPE_ARP,
                 REST_DL_TYPE_IPV4: ether.ETH_TYPE_IP,
                 REST_DL_TYPE_IPV6: ether.ETH_TYPE_IPV6},
                REST_NW_PROTO:
                {REST_NW_PROTO_TCP: inet.IPPROTO_TCP,
                 REST_NW_PROTO_UDP: inet.IPPROTO_UDP,
                 REST_NW_PROTO_ICMP: inet.IPPROTO_ICMP,
                 REST_NW_PROTO_ICMPV6: inet.IPPROTO_ICMPV6}}

    @staticmethod
    def to_rest(openflow):
        of_match = openflow['match']

        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == 'dl_src' or key == 'dl_dst':
                if value == mac_dontcare:
                    continue
            elif key == 'nw_src' or key == 'nw_dst':
                if value == ip_dontcare:
                    continue
            elif key == 'ipv6_src' or key == 'ipv6_dst':
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            if key in Match._CONVERT:
                conv = Match._CONVERT[key]
                conv = dict((value, key) for key, value in conv.items())
                match.setdefault(key, conv[value])
            else:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_mod_openflow(of_match):
        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == 'dl_src' or key == 'dl_dst':
                if value == mac_dontcare:
                    continue
            elif key == 'nw_src' or key == 'nw_dst':
                if value == ip_dontcare:
                    continue
            elif key == 'ipv6_src' or key == 'ipv6_dst':
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            match.setdefault(key, value)
        
        return match


class Action(object):

    @staticmethod
    def to_rest(flow): #represents info about action field to user
        if 'actions' in flow:
            actions = []
            for act in flow['actions']:
                ip_dst = re.search('SET_FIELD: \{ipv4_dst:(\d+\.\d+\.\d+\.\d+)', act)
                if ip_dst:
                    actions.append({'ipv4_dst': ip_dst.group(1)})
                ip_src = re.search('SET_FIELD: \{ipv4_src:(\d+\.\d+\.\d+\.\d+)', act)
                if ip_src:
                    actions.append({'ipv4_src': ip_src.group(1)})
                dst_value = re.search('SET_FIELD: \{tcp_dst:(\d+)', act)
                if dst_value:
                    actions.append({'tcp_dst': dst_value.group(1)})
                src_value = re.search('SET_FIELD: \{tcp_src:(\d+)', act)
                if src_value:
                    actions.append({'tcp_src': src_value.group(1)})
                output_value = re.search('OUTPUT:(\d+)', act)
                if output_value:
                    actions.append({'OUTPUT': output_value.group(1)})
            action = {'actions': actions}
        else:
            action = {'actions': 'Unknown action type.'}
        
        return action

 
