This is the Main Controller of of the DIPA pulsar architecutre

This file classifies botnet flows , applying the following rules :
1) Ingress policy rate ( QoS ) on parent bot switches
2) Block 48101 traffic to stop botnet malware loading
3) Classifies CNC through biased telnet traffic , block flows from this IP
4) Blocks port 23 and 2323 if the network is >= 50% compromised

Upon Classification , neighbouring Domains are alerted of any malicious activity
from this source domains.

Follow the Complete installation guide on the home page to use this file 

To run this File use :

ryu run DIPA_controller.py

or

ryu-manager DIPA_Controller.py
