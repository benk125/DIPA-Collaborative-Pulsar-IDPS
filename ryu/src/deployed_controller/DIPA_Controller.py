########################################################################################
#											#	
#		ELE4001 - Final Year Project						#
#		40133635 Ben Kelly 							#
#		Collaborative Intrusion Detecton and prevention system (DIPA)		#
#											#
#		This piece combnes a coarse grain intrusion detection sytem 		#
#		to classify mirai botnet Attacks. This system is used to 		#
#		detect suspicious bots and the suspected controller within 		#
#		the network , and writing prioiryt drop flow rules to mitigate		#
#		this piece also applies QoS policy rate limitations to deter		#
#		the attacker. This piece is designed to utilize Apache pulsar's		#
#		pub sub framework to collaborative protect neighbouring system		#
#		subscribed to set topics. 						#
#											#
#		NOTE : Requirements specified in Github ReadMe. Proof of Concept	#
#		       So may require tweaks to introduce a comprehensive NIDs		#
#											#
#########################################################################################

# Import RYu controller libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto
from ryu.app import simple_switch_13
from ryu.lib import hub
from ryu.controller import dpset


# import Threading and timiing libraries
from operator import attrgetter
from pulsar import ConsumerType, PartitionsRoutingMode
import time
from datetime import datetime, timedelta
import pulsar
import threading 
import subprocess
import collections
import numpy as np
import operator


# Set Global semaphore to prvent Global Interpreter Lock
# Semaphore lock used between statRequest and pulsar consumption
sem = threading.Semaphore()

# Declare Global fat tree switch dict for port statistics
traf_dict = {}
for i in range(1,9):
    traf_dict['10.0.0.{}'.format(i)] = {}

# Set Client to connect to local or remote pulsar service UrL
# For deploymnet usage URL change requried. 
client = pulsar.Client('pulsar://192.168.42.4:6650')

# Main Alert client consumer
consumer = client.subscribe('persistent://public/standalone/1/mirai',
                            'sub',
                            consumer_name='Vm-1 Sub',
                            consumer_type=ConsumerType.Shared,
                            broker_consumer_stats_cache_time_ms=100000)

# Main LAN alert producer
producer = client.create_producer('persistent://public/standalone/1/mirai',
                    		  send_timeout_millis=0,
				  compression_type=pulsar.CompressionType.ZLib,
				  producer_name='VM-1 Prod',
				  max_pending_messages_across_partitions=500000,
				  block_if_queue_full=False,
				  message_routing_mode=PartitionsRoutingMode.RoundRobinDistribution)
		     
# WOP : Global view for flow statistics update to monitor hub
producerUpdate = client.create_producer(
                    'non-persistent://sample/standalone/update/update0',
                )

# Testing : Producer to send Control plane and detection processing time
producerTime = client.create_producer(
                    'non-persistent://sample/standalone/timer/time0',
                )

# Global Dictionary to meaasure biased telnet traffic in system
bot_dict = {}
cnc_traffic_dict= {'10.0.0.2' : 0 ,'10.0.0.3' : 0,'10.0.0.5': 0,'10.0.0.6': 0,'10.0.0.7':0}
mean_dict = {'10.0.0.1': 0 ,'10.0.0.2' : 0 ,'10.0.0.3' : 0, '10.0.0.4' : 0 ,'10.0.0.5': 0,'10.0.0.6': 0,'10.0.0.7':0, '10.0.0.8':0}


## NOTE : Modified RYu SimpleSwitch 13 
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.mac_to_port = {}
        self.datapaths = {}

        # Iniitialise set to determine bots and suspected CNC
        self._cnc_ip=''
        self._newBots = set()
        self._suspected_bots = set()

        # run stasrequest and pulsar consumption on sperate threads to add parallelism
        self.monitor_thread = threading.Thread(target=self._monitor)
        self.monitor_thread2 = threading.Thread(target=self._monitor2)
        self.monitor_thread2.start()
        self.monitor_thread.start()

	# Class variable for testing 
        self.collabTrig=0
        self.protoTrig=0
        self.timeRequest =0
        self.timeReply=0
 
        # Stack of the five previous telent flows to find mean and standard deviaiton
        self.telnetStack = collections.deque([],8)

        # NUmber of flows and requests that each switch stores
	# NOTE : Open VSwitch max is ~7500
        self.req1=[0]*10000
        self.diff=[0]*10000

        # STatic reference of the fat tree to show links between nodes and find edge 
        self.portMaps = {"s1": ["s2", "s5"],
                        "s2": ["s3", "s4"],
                        "s3": ["10.0.0.1", "10.0.0.2"],
                        "s4": ["10.0.0.3", "10.0.0.4"],
                        "s5": ["s6", "s7"],
                        "s6": ["10.0.0.5", "10.0.0.6"],
                        "s7": ["10.0.0.7", "10.0.0.8"]}



    # ---------------------Define protocol type on packetIn-----------------------#
    def getProtocol(self, pkt, parser, in_port, dst,src, protoTrig,collabTrig):

	# Read the packet in an determine its type
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)
        arp_pkt = pkt.get_protocol(arp.arp)
        port = 0
        if tp:
                port = tp.dst_port
        ud = pkt.get_protocol(udp.udp)
        if ud:
                port = ud.dst_port

	# In the event of an IPV4 packet (IPV6 out of project scope)
        if pkt_ipv4:
		
		# Find pkts src and dst 
                protocol = pkt_ipv4.proto
                src = pkt_ipv4.src
                dst = pkt_ipv4.dst

		# Reduce packet type by matching based on port
		# Extra protocol deductions not needed, Main function = Telnet deducation
		# Check For ICMP
                if protocol==1 or protoTrig =="1":
                        return "ICMP" ,1, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=1, tcp_dst=2)

		# CHeck For TCP protocols
                if protocol==6 or protoTrig=="6":
                        if port==80 or collabTrig=="HTTP":
                                return "HTTP",6, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=80)
                        if port==443 or collabTrig=="HTTPS":
                                return "HTTPS",6, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=6,tcp_dst=443)
                        if port==23 or collabTrig=="Telnet":
                                return "Telnet",6, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=23)
                        return "TCP",6, parser.OFPMatch(in_port=in_port, ipv4_dst=dst, ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=port)

		# Check for UDP protocols
                if protocol==17 or protoTrig=="17":
                        if port==53 or collabTrig=="DNS":
                                return "DNS",17, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=17, udp_dst=53, udp_src=48101)
                        if port==67 or collabTrig=="DHCP":
                                return "DHCP",17, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=17, udp_dst=67)
                        return "UDP",17, parser.OFPMatch(in_port=in_port, ipv4_dst=dst,ipv4_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=17, udp_dst=port)

	# If not one of the speicifed functions , dont write a flow rule
        return "Unknown", 10, parser.OFPMatch(in_port=in_port)


    # Handles Switch COnfiguration ( I.e Make sure each switch is using OpenFlow v1.3)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

	# Add preliminary flow rules to hit controller if flow not found on switches
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add flow to speificied datapath (switch) 
    # Rule should remain on switches for 60 if not used
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=100, idle_timeout=60)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=100, idle_timeout=60)
        datapath.send_msg(mod)


    # In the event a packet is not found on the switch , hit this functions
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

	# Determine the packet type
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

	# Determine the packet type
        protocol,protoNum, matchpkt = self.getProtocol(pkt, parser, in_port, dst,src,self.protoTrig, self.collabTrig)

        key = "%s %s %s" % (src, dst, protocol)


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and protocol != "Unknown":
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, matchpkt, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, matchpkt, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # Monitor traffic statisitics on first monitor thread
    def _monitor(self):
        while True:
            while not sem.acquire(blocking=False):
                time.sleep(0.5)
            else:
		# Check Flow Stats for each switch and update dictionary fields
                for dp in self.datapaths.values():
                    self._request_stats(dp)
                    time.sleep(0.5)
                self.mirai_checker()
            sem.release()
	    # Wait 2 seconds before polling for statistics traffic again
            time.sleep(1.5)

    # classify botnet attack
    def mirai_checker(self):

        # if there is a suspected bot
        if(bool(self._suspected_bots) == True):
             for keyss in (self._suspected_bots - self._newBots):
                    self._newBots.add(keyss)

		    # Combine previously suspected bots with newly discovered
                    self._full_bots = self._suspected_bots.union(self._newBots)
		    # Alert the pulsar topic of the suspected BOT IPS
                    producer.send_async(("{}@{}".format(keyss, "BOT",  
		                                        replication_clusters='us-west-2a',
							partiton_key=RoundRobinPartition,
							event_timestamp=True)).encode('utf-8'))

             # Alert destination domains of suspected CNC commander
             producer.send_async(("{}@{}".format(self._cnc_ip, "CNC",
						 replication_cluster='us_west-2a',
						 partition_key=RoundRobinPartition,
						 event_timestamp=True)).encode('utf-8'))

             # Add these bots to a blacklistfor the system to remember
             self._newBots.add(keyss)
             self._full_bots = self._suspected_bots.union(self._newBots)
             print("Suspected_bots " , self._full_bots)
             probabil = (len(self._full_bots) / len(mean_dict)) * 100

	     # IF the network becomes more than 50% compromied, Stop all telnet communications
             if (probabil >= 50 ):
                 producer.send(("{}@{}".format(self._cnc_ip, probabil)).encode('utf-8'))


    # Thread 2 : receive data producer to its consumer topics 
    # parse device type send over network and apply mitgiate defences
    def _monitor2(self):
	# Allow initial pulsar connection to setup before trying to consume
        time.sleep(5)
        while True:
            while not sem.acquire(blocking=False):
                time.sleep(0.5)
            else:
                try:
		
		    # Try Consume Data on the consumer Topic with TTL of 100ms
                    msg = consumer.receive(timeout_millis=100)
                    data = msg.data().decode('utf-8')

		    # Parse the packets and use regex to remove unwanted parenthis
                    flowValues = data.split("@")
                    ip_add = flowValues[0].replace("{*/\}",'')
                    device = flowValues[1].replace('{*/\}','')


		    # IF bot device detected , apply ingress to its parent switch to deter the attack 
                    if device == "BOT":
                        attackerSwitch, attackerPort = self.getSwitch(ip_add)
                        print("applying ingress for bot : {}  on Switch {}:".format(ip_add, attackerSwitch))
                        ingressPolicingBurst ="ingress_policing_burst=1"
                        ingressPolicingRate ="ingress_policing_rate=0"
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingBurst])
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingRate])

                    dp = self.dpset.get_all()
                    for datapath in dp:              
                        ofproto = datapath[1].ofproto
                        parser = datapath[1].ofproto_parser
                        act = [] 

			# FOr each switch in the LAN , block all loading traffic on port 48101
                        if u == "BOT":
                            mat1 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=48101, ipv4_src=s)
		            # Add flow rule with higher priority to makes sure it hits this first
                            self.add_flow(datapath[1],100,mat1,act)

			# If The suspected Device is the commander, Block telnet outgress telnet traffic
                        elif u == "CNC": 
                            print("Flow Rule Write for suspected CNC : {} on Switch {}".format(s, datapath[0]))

			    # Block traffic on both telnet ports , 23 and 2323
                            mat1 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=23,ipv4_src=s)
                            mat2 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=2323,ipv4_src=s)
                            self.add_flow(datapath[1],100,mat1,act)
                            self.add_flow(datapath[1],100,mat2,act)

			# If a large proportion of the network is Compromised on a neigbouring domain, shut of all telent connections for a 100 seconds
                        else:
                            print("The CNC has enslaved {} of the Network, ceasing all telnet on Switch {}".format(u, datapath[0]))
                            mat1 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=23)
                            mat2 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, tcp_dst=2323)
                            self.add_flow(datapath[1],100,mat1,act)
                            self.add_flow(datapath[1],100,mat2,act)

		    # Acknowledge the message , this will delete the partiton from the backlog and queue
                    consumer.acknowledge(msg)
                except Exception:
                    print("Not found in 10 seconds")
                
            sem.release()
            time.sleep(0.5)


    # This function request flow statistics from each of the switches to be analayzed
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath)
        datapath.send_msg(req)

	# Testing : Used to record control plane time 
        self.timeRequest = time.perf_counter()


    # Used to determine whih swtich a given IP belows to , Used portMaps dictionary declared at start
    def getSwitch(self, node):
        for switch in self.portMaps:
            if node in self.portMaps[switch]:
                return switch, str(self.portMaps[switch].index(node) + 1)


    # In the event of flow stats being return , classify the attack by
    #  determining the packet flow rate over the last 5 flows
    # if device/IP exhibit given features of a botnet , flag as suspicious
    # by placing in dictionary. Updates to this dictionary are send to neigbbouring 
    # Domains.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        value=0
        body = ev.msg.body

	# ONly check flows that dont contain block rules
	# Prevent reprocessing on multiple block flow rules
        for stat in sorted([flow for flow in body if flow.priority == 10],
                           key=lambda flow: (flow.match['in_port'])):
            value =value+1
            self.diff[value] = (stat.packet_count - self.req1[value])
            self.req1[value] = stat.packet_count

	    # IF the flow seems to load traffic from 48101 flag as  suspicious bot
	    # Add new bot to dict to collect statistics of its telnet flow to see if
	    # it is communicating with someone
            try:
                if(stat.match['udp_dst'] == 48101 and stat.match['udp_src'] == 48101):
                    if stat.match['ipv4_src'] not in bot_dict:
                        bot_dict[stat.match['ipv4_src']] = 0.0
            except:
                pass

	    # IF Telnet traffic is detected in flow statistics , CHeck its direction
	    # Is the flow Statistics biased , is packet count too high in one direction
            try:
                if(stat.match['tcp_dst'] == 23):
                    traf_dict[stat.match['ipv4_src']] = {stat.match['ipv4_dst'] : stat.packet_count}
                    for keygo , valuego in traf_dict.items(): 
                        mean_dict[keygo] = sum(traf_dict[keygo].values())

			# Find Ip address which has the most unidrectional telnet traffic and 
			# flag as a bot
                        self._cnc_ip = max(mean_dict.items(), key=operator.itemgetter(1))[0]
			
	            # determin the mean of the traffic for each bot
                    if stat.match['ipv4_src'] != self._cnc_ip:
                        bot_dict[stat.match['ipv4_src']] = (1 - (stat.packet_count / (stat.packet_count + mean_dict[self._cnc_ip])))

            except:
                pass
            
	    # Bots are only flagged as suspected if they have 48101
	    # bots are only suspicuous if they have 48101 traffic and their mean telnet
	    # traffic between it and the controller if greater than 60% of its normal traffic
            self._suspected_bots = set((k) for k,v in bot_dict.items() if v >= 0.6)

        self.timeReply = time.perf_counter()
        nowTime = datetime.now()
        producerTime.send("{}@{}".format(self.timeReply - self.timeRequest, nowTime).encode('utf-8'))

            
