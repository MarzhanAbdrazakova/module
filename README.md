# module

tcp_port.py, port.py - script, which make REST API requests to controller to add port forwardings in flow table.
rest_forward.py - ryu app, processes REST API requests to make changes in flow table. 


1) start rest_forward.py app: 
 > sudo ryu-manager rest_forward.py 
2) on Mininet run a network of 2 hosts, 1 switch 
 > sudo mn –controller remote -x
3) start xterm for c0:
 > xterm c0
4) set OpenFlow13 for the OpenFlow version:
 > ovs-vsctl set Bridge s1 protocols=OpenFlow13
5) on c0 run tcp_port.py and port.py:
 > python ./tcp_port.py ,
 > python ./port.py -
   enter port values
6) check flow table:
 > curl –X GET http://localhost:8080/forward/rules/0000000000000001
7) delete rule:
 > curl -X DELETE -d '{"rule_id": '1' }' http://localhost:8080/forward/rules/0000000000000001
   

   





