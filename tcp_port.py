#!/usr/bin/python

import requests
import json

def rest(tcp1,tcp2,inport,outport):

    url = 'http://localhost:8080/forward/rules/0000000000000001'
    payload = { "dpid": 1, "priority":100, "match": { "nw_dst": "10.0.0.2", "nw_proto": "TCP", "eth_type": 2048, "tcp_dst": tcp1, "in_port": inport}, "actions":  { "tcp_dst": tcp2, "OUTPUT":outport}  }
    r=requests.post(url, json.dumps(payload))

    payload = { "dpid": 1, "priority":100, "match": { "nw_src": "10.0.0.2", "nw_proto": "TCP", "eth_type": 2048, "tcp_src": tcp2, "in_port": outport}, "actions": { "tcp_src": tcp1, "OUTPUT":inport} }
    r=requests.post(url, json.dumps(payload))
    
def main():
    x = input("Enter tcp port 1: ")
    y = input("Enter tcp port 2: ")
    z = input("Enter in_port: ")
    h = input("Enter output port: ")
    rest(x,y,z,h)
    

if __name__ == '__main__':
    main()
