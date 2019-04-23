from operator import attrgetter

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import socket
import threading
import socketserver
import subprocess
import logging
import pulsar
from pulsar import ConsumerType
import pickle
import ast
import json

client = pulsar.Client('pulsar://192.168.1.1:6650')

producer = client.create_producer(
                    'my-topic',
                )

class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

# Logging configuration
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.INFO)
logging.getLogger("ofp_event").setLevel(logging.WARNING)
#logging.getLogger().addHandler(logging.StreamHandler())


# Receiving requests and passing them to a controller method,
# which handles the request
class RequestHandler(socketserver.BaseRequestHandler):

    # Set to the handle method in the controller thread
    handler = None

    def handle(self):
        data = self.request.recv(1024)
        RequestHandler.handler(data)


# Simple TCP server spawning new thread for each request
class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


# Client for sending messages to a server
class Client:

    # Initialize with IP + Port of server
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    # Send an arbitrary message given as a string
    # Starts a new thread for sending each message.
    def send(self, message):
        def do():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            try:
                sock.sendall(message)
                response = sock.recv(1024)
            finally:
                sock.close()

        thread = threading.Thread(target=do)
        thread.daemon = True
        thread.start()

# The main controller script, extends the already exisiting
# ryu script simple_switch_13
class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    
    # Interval for polling switch statistics
    QUERY_INTERVAL = 2
    # Bandwith threshold in Kbit/s for assuming an attack
    # on a port
    ATTACK_THRESHOLD = 4000
    # Bandwith threshold in Kbit/s for assuming that the
    # attack has stopped after applying an ingress policy
    PEACE_THRESHOLD = 10
    # Number of repeated poll statistics measurements to 
    # assume that the judgement on either "attack over"
    # "host under DDoS attack" is correct.
    SUSTAINED_COUNT = 5

    # Bandwidth threshold in Kbit/s for assuming that a particular
    # host is launching a DDoS attack
    ATTACKER_THRESHOLD = 1000
    # Specifies if polled switch statistics should reported on stout
    REPORT_STATS = True
	
    def __init__(self, *args, **kwargs):
        # Monitoring
        super(SimpleMonitor, self).__init__(*args, **kwargs)

	    # Set of currently known (assumed) attackers
        self.attackers = set()
        # Sustained counts for the above judgements
        self.sustainedAttacks, self.sustainedPushbackRequests = 0, 0
        # Indicates for each switch to which of its ports we applied an ingress policy
        self.ingressApplied = {"s1": [False, False, False],
                               "s11": [False, False, False],
                               "s12": [False, False, False],
                               "s21": [False, False, False],
                               "s22": [False, False, False],
                               "s2": [False, False, False]}

    	# Sustained no attack count for switch/port combinations
        self.noAttackCounts = {"s1":  [0] * 3,
                               "s11": [0] * 3,
                               "s12": [0] * 3,
                               "s21": [0] * 3,
                               "s22": [0] * 3,
                               "s2":  [0] * 3}

        # Mapping from switch/port/destination MAC combinations to flow rates
        self.rates = {"s1": [{}, {}, {}], 
                      "s11": [{}, {}, {}], 
                      "s12": [{}, {}, {}], 
                      "s2": [{}, {}, {}], 
                      "s21": [{}, {}, {}], 
                      "s22": [{}, {}, {}]}
        
        # Mapping from switches and ports to
        # attached switchtes/hosts
        self.portMaps = {"s1": ["s11", "s12", "s2"],
                        "s11": ["AAh1", "AAh2", "s1"],
                        "s12": ["ABh1", "ABh2", "s1"],
                        "s21": ["BAh1", "BAh2", "s2"],
                        "s22": ["BBh1", "BBh2", "s2"],
                        "s2": ["s21", "s22", "s1"]}

        self.IPMaps = {"s1": ["s11", "s12", "s2"],
                        "s11": ["10.1.1.1", "10.1.1.2", "s1"],
                        "s12": ["10.1.2.1", "10.1.2.2", "s1"],
                        "s21": ["10.10.10.1", "10.10.10.2", "s2"],
                        "s22": ["10.10.20.1", "10.10.20.2", "s2"],
                        "s2": ["s21", "s22", "s1"]}

        self.MACMaps = {"s1": ["s11", "s12", "s2"],
                        "s11": ["0a:0a:00:00:00:01", "0a:0a:00:00:00:02", "s1"],
                        "s12": ["0b:0b:00:00:00:01", "0a:0b:00:00:00:02", "s1"],
                        "s21": ["0a:0b:0a:00:00:01", "0a:0b:0a:00:00:02", "s2"],
                        "s22": ["0a:0b:0b:00:00:01", "0a:0b:0b:00:00:02", "s2"],
                        "s2": ["s21", "s22", "s1"]}


        # Mapping from datapath ids to switch names
        self.dpids = {0x1: "s1", 
                 0xb: "s11",
                 0xc: "s12",
                 0x2: "s2",
                 0x15: "s21",
                 0x16: "s22"}

        # Flow datapaths identified by statistics polling
        self.datapaths = {}
        # Last acquired byte counts for each FLOW
        # to calculate deltas for bandwith usage calculation
        self.flow_byte_counts = {}
        # Last acquired byte counts for each PORT
        # to calculate deltas for bandwith usage calculation
        self.port_byte_counts = {}
        # Thread for polling flow and port statistics
        self.monitor_thread = hub.spawn(self._monitor)

        #self.monitor_pulsar = hub.spawn(self._pulsar)

        # Pushback state
        # Set of hosts, which we suspect to be victims of an attack originating
        # in the other network
        self.pushbacks = set()
        # Set of hosts in other domain to which we were reported an attack
        self.other_victims = set()
       
###########################################
# Server Code
###########################################

        # Lock for the set of victims reported by the other server
        
        self.lock = threading.Lock()
        # IP + PORT for the TCP Server on this controller
        ip, port = "localhost", 2000
        # IP + PORT for the TCP Server on the other controller
        ip_other, port_other = "localhost", 2001

        # Handler for incoming requests to the server
        RequestHandler.handler = self.handlePushbackMessage

        # Server instance
        self.server = Server((ip, port), RequestHandler)

        # Initiate server thread
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Server thread will terminate when controller terminates
        server_thread.daemon = True
        server_thread.start()

        # Start client for sending pushbacks to the other server
        self.client = Client(ip_other, port_other)

    # Handler receipt of a pushback message
    def handlePushbackMessage(self, data):
        victim = data.strip()[len("Pushback attack to "):]
        print("Received pushback message for victim: %s" % victim)
        # Avoid race conditions for pushback messages
        self.lock.acquire()
        try:
            self.other_victims.add(victim)
        finally:
            self.lock.release()

###########################################
# Monitoring Code
###########################################
    # Handler for registering new datapaths
    # Taken from http://osrg.github.io/ryu-book/en/html/traffic_monitor.html

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                #logging.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                #logging.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # Main function of the monitoring thread
    # Simply polls switches for statistics
    # in the interval given by QUERY_INTERVAL
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(SimpleMonitor.QUERY_INTERVAL)

    # Helper function for polling statistics of a datapath
    # Taken from http://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    def _request_stats(self, datapath):
        #logging.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # Handler for receipt of flow statistics
    # Main entry point for our DDoS detection code.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        domainHosts = ['0a:0a:00:00:00:01', '0a:0a:00:00:00:02', '0a:0b:00:00:00:01', '0a:0b:00:00:00:02']
        
        # The (suspected) set of victims identified by the statistics
        victims = set()

        body = ev.msg.body
        # Get id of datapath for which statistics are reported as int
        dpid = int(ev.msg.datapath.id)
        switch = self.dpids[dpid]

        if SimpleMonitor.REPORT_STATS:
            print("-------------- Flow stats for switch ", switch," ---------------")
        
        # Iterate through all statistics reported for the flow
        for stat in sorted([flow for flow in body if flow.priority == 10],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            # Get in and out port + MAC dest of flow
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']

            # Check if we have a previous byte count reading for this flow
            # and calculate bandwith usage over the last polling interval
            key = (dpid, in_port, eth_dst, out_port)
            rate = 0
            if key in self.flow_byte_counts:
                cnt = self.flow_byte_counts[key]
                rate = self.bitrate(stat.byte_count - cnt)
            self.flow_byte_counts[key] = stat.byte_count
            if SimpleMonitor.REPORT_STATS:
                print("In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate))

            # Save the bandwith calculated for this flow
            self.rates[switch][in_port - 1][str(eth_dst)] = rate

            # If we find the bandwith for this flow to be higher than
            # the provisioned limit, we mark the corresponding
            # host as potential vicitim
            if rate > SimpleMonitor.ATTACK_THRESHOLD:
                self.noAttackCounts[switch][in_port - 1] = 0
                victim = str(eth_dst)
                if victim in domainHosts:  # If not in domain, ignore it. (Will be handled by pushback requests)
                    victims.add(victim)

        for stat in sorted([flow for flow in body if flow.priority == 10000],
                           key=lambda flow: (flow.match['ipv4_src'])):
            blocked_src = stat.match['ipv4_src']

            print("Blocked Ips: {}".format(blocked_src))

        for stat in sorted([flow for flow in body if flow.priority == 10001],
                           key=lambda flow: (flow.match['eth_src'])):
            blocked_MAC = stat.match['eth_src']

            print("Blocked MACs: {}".format(blocked_MAC))



        #for stat in sorted([flow for flow in body if flow.priority == 1],
        #                   key=lambda flow: (flow.match['ipv4_src'])):
        #    print("Drop Attack Flow Rule")

        

        # Calculate no sustained attack counts
        for port in range(len(self.ingressApplied[switch])):
            if not self.ingressApplied[switch][port]:
                continue  # If ingress is not applied, skip

            # If rate for all flows on the links is below safe level,
            # increase the sustained no attack count for this link
            if all(x <= SimpleMonitor.PEACE_THRESHOLD for x in self.rates[switch][port].values()):
                self.noAttackCounts[switch][port] += 1
            else:
                self.noAttackCounts[switch][port] = 0
        
        victims = victims.intersection({'0a:0a:00:00:00:01', '0a:0a:00:00:00:02'})  # only consider the protected hosts
        
        # Handle pushback requests from the other host
        self.dealWithPushbackRequests()

        # Identify the set of victims attacked by hosts located in the other domain
        # and directly apply policies to the attackers in the local domain
        pushbacks = self.dealWithAttackers(victims, ev.msg.datapath)
        
        if pushbacks == self.pushbacks and len(pushbacks) > 0:            # Send pushback messages
            self.sustainedPushbackRequests += 1
            logging.debug("Sustained Pushback Count %s" % str(self.sustainedPushbackRequests))
            if self.sustainedPushbackRequests > SimpleMonitor.SUSTAINED_COUNT:
                for victim in pushbacks:
                    self.client.send("Pushback attack to " + victim)
                self.sustainedPushbackRequests = 0
        elif len(pushbacks) > 0:
            self.sustainedPushbackRequests = 0
            self.pushbacks = pushbacks

        self.checkForIngressRemoval(victims)  # If there are no victims, for a sustained duration, try remove ingress policies

        if SimpleMonitor.REPORT_STATS:
            print("--------------------------------------------------------")
        

    # Handle pushback requests issued by the controller in the other domain
    def dealWithPushbackRequests(self):
        victims = set()
        # Avoid race conditions pertaining to pushbacks
        self.lock.acquire()
        try:
            victims = self.other_victims
            self.other_victims = set()
        finally:
            self.lock.release()
        
        for victim in victims:
            # Identify attackers for the victims
            victimAttackers = self.getAttackers(victim)
            print("Responding to pushback request, applying ingress on %s to relieve %s" % (victimAttackers, victim))
            # Apply an ingress policy to each attacker
            for attacker in victimAttackers:
                self.applyIngress(attacker)

    def send_callback(producer, msg, b):
        print('Callback : ', msg)

    # Identify the set of victims attacked by hosts located in the other domain
    # and directly apply policies to the attackers in the local domain
    def dealWithAttackers(self, victims, datapath):
        # Set of victims attacked by the other domain
        pushbacks = set()
        # Set of attackers in the local domain
        attackers = set()
        attackersMAC = set()
        attackersIP = set()
        for victim in victims:
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            print("Identified victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort))
            victimAttackers = self.getAttackers(victim)
            print("Attackers for vicim %s: %s" % (victimAttackers, victimHost))
            attackersMacs, attackersIPs = self.getAttackersMac_IP(victim)
            #producer.send(("{}@{}@{}@{}".format(datapath.id,victimPort,victim,victimAttackers)).encode('utf-8'))
            producer.send(("{}@{}".format(attackersMacs, attackersIPs,)).encode('utf-8'))

            if not victimAttackers:
                # No attackers identified, thus assume it's originating in the other domain
                pushbacks.add(victim)
            else:
                attackers = attackers.union(victimAttackers)
        
        # Increase the count for confidence in a suspected attack
        # by the identifed attacker set if applicable
        if attackers:
            self.sustainedAttacks += 1
            logging.debug("Sustained Attack Count %s" % (self.sustainedAttacks / 3)) 
        else:
            self.sustainedAttacks = 0

        # If we have exceeded the confidence count for the local attacker
        # set, apply ingress policies to all attackers
        if self.sustainedAttacks / 3 > SimpleMonitor.SUSTAINED_COUNT:
            for attacker in attackers:
                self.applyIngress(attacker)

        return pushbacks
        
    # Check if the ingress policy should be removed for any port
    def checkForIngressRemoval(self, victims):
        # If the confidence count for no ongoing attack exceeds the provisioned limit
        # check if the bandwith consumption on one of the rate-limited links
        # dropped below a "safe" level and remove ingress policy
        for switch in self.ingressApplied:  # Iterate through all switches/ports
            for port in range(len(self.ingressApplied[switch])):
                # If rate for all flows on the links for this port have been below a safe level
                # for the last couple of statistic readings, remove the ingress policy
                if self.noAttackCounts[switch][port] >= self.SUSTAINED_COUNT and self.ingressApplied[switch][port]:
                    self.removeIngress(self.portMaps[switch][port])

    # Applies ingress to a given attacker's switch/port
    def applyIngress(self, attacker, shouldApply=True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.ingressApplied[attackerSwitch][int(attackerPort) - 1] == shouldApply:
            return

        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        if shouldApply:
            self.noAttackCounts[attackerSwitch][int(attackerPort) - 1] = 0
            print("Applying ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))
            ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=100", "ingress_policing_rate=40"
        else:
            print("Removing ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))

        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingBurst])
        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingRate])
        self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = shouldApply

    # Removes ingress at the given attacker's switch/port
    def removeIngress(self, attacker):
        self.applyIngress(attacker, False)

    # Returns the victim's switch, and port it is connected to
    def getVictim(self, victim):
        victimHost = victim[1].upper() + victim[4].upper() + "h" + victim[16]
        for switch in self.portMaps:
            for port in range(len(self.portMaps[switch])):
                if self.portMaps[switch][port] == victimHost:
                    return victimHost, switch, str(port + 1)

    # Returns the local attackers of a given victim
    def getAttackers(self, victim):
        attackers = set()
        for switch in self.rates:
            for port in range(len(self.rates[switch])):
                if victim not in self.rates[switch][port]:
                    continue
                if self.rates[switch][port][victim] > SimpleMonitor.ATTACKER_THRESHOLD:
                    attacker = self.portMaps[switch][port]
                    if not self.isSwitch(attacker):
                        attackers.add(attacker)
                    
        return attackers

    def getAttackersMac_IP(self, victim):
        attackersMAC = set()
        attackersIP = set()
        for switch in self.rates:
            for port in range(len(self.rates[switch])):
                if victim not in self.rates[switch][port]:
                    continue
                if self.rates[switch][port][victim] > SimpleMonitor.ATTACKER_THRESHOLD:
                    MAC = self.MACMaps[switch][port]
                    IP = self.IPMaps[switch][port]
                    if not self.isSwitch(MAC):
                        attackersMAC.add(MAC)
                        attackersIP.add(IP)

        return attackersIP, attackersMAC


    @staticmethod
    def isSwitch(victim):
        return victim[0] == "s"

    def getSwitch(self, node):
        for switch in self.portMaps:
            if node in self.portMaps[switch]:
                return switch, str(self.portMaps[switch].index(node) + 1)

    # Convert from byte count delta to bitrate
    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (SimpleMonitor.QUERY_INTERVAL * 1000)

    # Handle receipt of port traffic statistics
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)
            
            rx_bitrate, tx_bitrate = 0, 0
            if key in self.port_byte_counts:
                cnt1, cnt2 = self.port_byte_counts[key]
                rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
                tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.port_byte_counts[key] = (stat.rx_bytes, stat.tx_bytes)
