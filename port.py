#!/usr/bin/python

import requests
import json

def rest(inport,outport):

    url = 'http://localhost:8080/forward/rules/0000000000000001'
    payload = {"dpid": 1, "priority":10, "match": { "in_port": inport}, "actions": { "OUTPUT": outport} }
    r=requests.post(url, json.dumps(payload))

    payload = {"dpid": 1, "priority":10, "match": { "in_port": outport}, "actions": { "OUTPUT": inport} }
    r=requests.post(url, json.dumps(payload))
   
def main():
    z = input("Enter in_port: ")
    h = input("Enter output port: ")
    rest(z,h)
    
    

if __name__ == '__main__':
    main()
