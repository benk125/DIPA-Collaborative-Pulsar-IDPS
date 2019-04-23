from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto
from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.lib import hub
from ryu.controller import dpset
from pulsar import ConsumerType
import time
import pulsar

client = pulsar.Client('pulsar://192.168.1.1:6650')

consumer = client.subscribe('non-persistent://sample/standalone/ns/my-topic',
                            'my-sub',
                            consumer_type=ConsumerType.Shared)


producer = client.create_producer(
                    'non-persistent://sample/standalone/ns/my-topic', 
                )

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
        self.monitor_thread = hub.spawn(self._monitor)
        #self.monitor_thread = hub.spawn(self._monitor1)
        self.monitor_thread = hub.spawn(self._monitor2)
        self.req1=[0]*80
        self.diff=[0]*80


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


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

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)
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


    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3)


    def _monitor1(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats1(dp)
            hub.sleep(20)

    def _monitor2(self):
        hub.sleep(10)
        while True:
            hub.sleep(5)
            try:
                # try and receive messages with a timeout of 10 seconds
                msg = consumer.receive(timeout_millis=10000)

                print("Received message '{}' id= '{}'".format(msg.data() , msg.message_id()))

                data = msg.data().decode('utf-8')
                flowValues = data.split("@")
                s = flowValues[0].replace('{','')
                s = s.replace('\'', '')
                s = s.replace('}', '')
                dp = self.dpset.get_all()
                #dp = dp[1][1]
                for datapath in dp:              
                    #print("Dp :" , dp)
                    ofproto = datapath[1].ofproto
                    parser = datapath[1].ofproto_parser
                    act = [] 
                    mat1 = parser.OFPMatch(eth_src=s)
                    #print("Match :", mat1)
                    self.add_flow(datapath[1],100,mat1,act)

                # Acknowledge processing of message so that it can be deleted
                consumer.acknowledge(msg)
            except Exception:
                print("No Flow in 10 seconds")




    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath)
        datapath.send_msg(req)


    def _request_stats1(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def send_get_async_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPGetAsyncRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPGetAsyncReply, MAIN_DISPATCHER)
    def get_async_reply_handler(self, ev):
        print("Got async reply")
        msg = ev.msg
        self.logger.info("\nAsync port info:")
        self.logger.info('packet_in_mask         '
                         'port_status_mask        '
                         'flow_removed_mask         ')
        self.logger.info('------------         -----------           ---------')
        self.logger.info('0x%08x:0x%08x         0x%08x:0x%08x        0x%08x:0x%08x',
                          msg.packet_in_mask[0],
                          msg.packet_in_mask[1],
                          msg.port_status_mask[0],
                          msg.port_status_mask[1],
                          msg.flow_removed_mask[0],
                          msg.flow_removed_mask[1])

    def send_aggregate_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,
                                                  ofp.OFPTT_ALL,
                                                  ofp.OFPP_ANY,
                                                  ofp.OFPG_ANY,
                                                  cookie, cookie_mask,
                                                  match)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info("\nAggregateStats:")
        self.logger.info('Packet Count         '
                         'Byte Count           '
                         'Flow Count           ')
        self.logger.info('------------         -----------           ---------')
        self.logger.info('%8d            %8d            %8d',
                         body.packet_count, body.byte_count,
                         body.flow_count)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        value=0
        body = ev.msg.body

        self.logger.info("\nLegitimate Traffic Flows in Switch S{}:".format(ev.msg.datapath.id))
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 10],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            try:
                if(flow.match['tp_src'] == 22):
                    print("Telnet traffic detected")
            except:
                pass
            value =value+1
            self.diff[value] = (stat.packet_count - self.req1[value])
            self.req1[value] = stat.packet_count
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            if((self.diff[value])/3 > 25):
                msg = ev.msg
                datapath = msg.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                act = [] 
                mat1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=stat.match['eth_src'])
                #self.add_flow(ev.msg.datapath,100,mat1,act)
                producer.send(("{}".format(stat.match['eth_src'])).encode('utf-8'))

        self.logger.info("\nDropped Flows in Switch S{}:".format(ev.msg.datapath.id))
        self.logger.info('datapath         '
                         'eth-src          '
                         'packets     bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '--------')

        for stat in sorted([flow for flow in body if flow.priority > 10],
                           key=lambda flow: (flow.match['eth_src'])):
            self.logger.info('%016x %8s %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['eth_src'], 
                             stat.packet_count, stat.byte_count)


    #def listener(self,consumer,msg):
        
        """
        data = msg.data().decode('utf-8')
        print("Attack Triggered")
        flowValues = data.split("@")
        s = flowValues[0].replace('{','')
        s = s.replace('\'', '')
        s = s.replace('}', '')
        #u = flowValues[1].replace('{','')
        #u = u.replace('\'', '')
        #u = u.replace('}', '')
        dp = self.dpset.get_all()
        consumer.acknowledge(msg)
        dp = dp[1][1]
        #print("Dp :" , dp)
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        act = [] 
        mat1 = parser.OFPMatch(eth_src=s)
        #print("Match :", mat1)
        self.add_flow(dp,100,mat1,act)

        #match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
        #mod = parser.OFPFlowMod(datapath=dp, table_id=0, priority=23, match=match)

        
        for dp in self.datapaths.values():
            print("Datapath :", dp)
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            act = [] 
            mat1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=s)
            self.add_flow(dp,100,mat1,act)

            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
            mod = parser.OFPFlowMod(datapath=dp, table_id=0, priority=23, match=match)
            print("Got to here")
            dp.send_msg(mod)

            #match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=u)
            #mod = parser.OFPFlowMod(datapath=datapath[1], table_id=0, priority=10001, match=match)
            #datapath[1].send_msg(mod)
        """
