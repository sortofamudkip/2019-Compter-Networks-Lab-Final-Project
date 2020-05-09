"""
connection rate
The idea is that hosts sending multiple things to other hosts without getting replies implies a ddos attack.
So a possible detection mechanism is: if a user is sending shit to too many hosts without getting replies, we shut them down.
Method:
0. create a table representing a bidiretional graph from host x to host y. Call it D. Initially it is just {}. 
1. when x sends something to y, check the table.

    if D[(x, y)] doesn't exist, set D[(x, y)] = 1 and D[(y, x)] = 0.
    else, D[(x, y)] already exists:
        if D[(y, x)] != 0: set D[(x, y)] and D[(y, x)] to 0 (this symbolizes that y has previously pinged x, and x is replying, so we reset both)
        else, D[(x, y)]++ (because x is pinging y)
        for take the sum of D[(x, z)] where z is any host, and if it is larger than 20, kill x.
    

    if (x, y) is in the table, check the value. 
"""

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types



class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # self.monitor_thread = hub.spawn(self._monitor)
        self.hosttable = {}      # port between host to switch
        self.connections = {}    # D[x][y]


    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
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

    def drop_host(self, switch, port):
        # dont' do anything yet; in theory this should drop all the packets coming from "port" to "switch"
        print "killing switch {} on port {}...".format(switch, port)
        switch = self.datapaths[switch]
        parser = switch.ofproto_parser
        match = parser.OFPMatch(in_port= port)
        actions = []
        self.add_flow(switch, 65535, match, actions)

    def print_important_message(self, host):
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"
        print "_______IMPORTANT NOTICE_________"
        print "host {} has too many connections!!!".format(host)
        print "host {} has too many connections!!!".format(host)
        print "host {} has too many connections!!!".format(host)
        print "host {} has too many connections!!!".format(host)
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"


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
        if src not in self.hosttable: 
            """
            this is used to learn the port between the switch and the host.
            """
            self.hosttable[src] = {"dpid": dpid, "in_port": in_port}

        """
        this is the connection rate thingy
        """
        if dst != "ff:ff:ff:ff:ff:ff": # don't consider talking to controller
            x = src; y = dst
            if (x, y) not in self.connections:
                print "({}, {}) not in".format(x, y) 
                self.connections[(x, y)] = 1
                self.connections[(y, x)] = 0
            else:
                print "({}, {}) in la".format(x, y) 
                if self.connections[(y, x)] != 0:
                    self.connections[(y, x)] = 0
                    self.connections[(x, y)] = 0
                else:
                    self.connections[(x, y)] += 1
            print self.connections
            Sum = {}
            for z in self.connections:
                x = z[0]; y = z[1]
                if x not in Sum: Sum[x] = self.connections[z]
                else: Sum[x] += self.connections[z]

            for host in Sum:
                if Sum[host] >= 20:
                    self.print_important_message(host)
                    switch = self.hosttable[host]["dpid"]
                    port = self.hosttable[host]["in_port"]
                    self.drop_host(switch, port) 

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
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                # return # jake: ?????
            else:
                self.add_flow(datapath, 1, match, actions)
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
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        return 
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        return
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
