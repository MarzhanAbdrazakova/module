#!/usr/bin/python

import requests
import json
import sys
import os

ip_contr=raw_input("IP address of controller: ")
dpid=raw_input("DPID of the switch: ")
url = 'http://'+ip_contr+':8080/forward/rules/'+dpid

while True:
    p="0"
    c = raw_input("1. Get flow table \n2. Set rule \n3. Delete rule \n4. Quit \n")
    if c == "3":
        rid = raw_input("Enter rule ID: ")
    elif c=="4":
	sys.exit(0)

    def get_table():
        table = requests.get(url)
        print table.text

    def delete_rule():
        os.system(" curl -X DELETE -d \'{\"rule_id\": % s}\' % s " % (rid, url))
  
    def tcp_inputs():
        in_port = raw_input("In_port: ")
        out_port = raw_input("Output port: ")
        ip_dest = raw_input("IP of destination host: ")
        tcp_from = raw_input("TCP port forward from: ")
        tcp_to = raw_input("TCP port forward to: ")
        prior = raw_input("Priority: ")
        tcp_ports(dpid, prior,ip_dest,in_port, out_port, tcp_from, tcp_to)

    def tcp_ports(dpid,prior,ip_dest, in_port, out_port, tcp_from, tcp_to):
        payload = { "dpid": dpid, "priority":prior, "match": { "nw_dst": ip_dest, "nw_proto": "TCP", "eth_type": 2048, "tcp_dst": tcp_from, "in_port": in_port}, "actions":  { "tcp_dst": tcp_to, "OUTPUT":out_port}  }
        r=requests.post(url, json.dumps(payload))

        payload = { "dpid": dpid, "priority":prior, "match": { "nw_src": ip_dest, "nw_proto": "TCP", "eth_type": 2048, "tcp_src": tcp_to, "in_port": out_port}, "actions": { "tcp_src": tcp_from, "OUTPUT":in_port} }
        r=requests.post(url, json.dumps(payload))

    if __name__ == '__main__':
        if c=="1":
            get_table()
       	elif c=="2":
            tcp_inputs()
        elif c=="3":
            delete_rule()
    
         
