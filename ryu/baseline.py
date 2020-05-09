from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.lib import hub
from pprint import pprint, pformat
from threading import Lock

class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.stp = kwargs['stplib']
        self.connections = {}

        self.saved_stats = {} #  datapath : (datapath result)
        self.prev_saved_stats = {} # same but for the previous 10 seconds

        self.hosttable = {}      # port between host to switch

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)
        # self.monitor_thread = hub.spawn(self._monitor)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in switch %s, source %s, dest %s, in_port %s", dpid, src, dst, in_port)

        if src not in self.hosttable: 
            """
            this is used to learn the port between the switch and the host.
            """
            self.hosttable[src] = {"dpid": dpid, "in_port": in_port}

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
            pprint( self.connections)
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

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # print "switch {} missed!! flooding...".format(dpid)
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

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
            # self.recieved_count = 0
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1.5) # make sure all the data has arrived
            self._process_data()
            hub.sleep(10)

    def _process_data(self):

        # print("====SAVED_DATA===="); pprint(self.saved_stats); print("====/SAVED_DATA====")
        # print("====PREV_SAVED_DATA===="); pprint(self.prev_saved_stats); print("====/PREV_SAVED_DATA====")
        # print("====MAC_TO_PORT===="); pprint(self.mac_to_port); print("====/MAC_TO_PORT====")
        # print("====HOST_TABLE===="); pprint(self.hosttable); print("====/HOST_TABLE====")
        # print("====OTHER_STUFF===")
        # find out how many packets each host sent

        # go through each value in saved_data to determine who is sending all the data
        offender = None # no one should be dropped yet
        for switch in self.saved_stats:
            if switch not in self.prev_saved_stats: continue
            ports = self.saved_stats[switch]; old_ports = self.prev_saved_stats[switch]
            for port in ports:
                if port not in old_ports: continue
                cur_bytes = ports[port]; prev_bytes = old_ports[port]
                differnce = cur_bytes - prev_bytes
                print "difference between switch {} port {}: {}".format(switch, port, differnce)
                THRESHOLD = 10000000
                if differnce >= THRESHOLD: # 10M
                    # kill the offender with the max
                    highest = -1
                    for host in self.hosttable:
                        switch_ = self.hosttable[host]["dpid"]; port = self.hosttable[host]["in_port"]
                        amount = self.saved_stats[switch_][port] - self.prev_saved_stats[switch_][port]
                        print "host {} sent {} bytes".format(host, amount)
                        if amount >= highest:
                            # self.print_important_message(host)
                            offender = {"host": host, "switch": switch_, "port": port}
                            highest = amount
                            # print "host {} is sending way too much data!!!".format(host)
        if offender:
            self.print_important_message(offender["host"])
            self.drop_host(offender["switch"], offender["port"])
        # print("====/OTHER_STUFF===")


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
        return # we don't need this function!!
        self.logger.debug('recieved data from: %016x', ev.msg.datapath.id)
        # self.recieved_count += 1
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
        body = ev.msg.body
        self.logger.debug('recieved data from: %016x', ev.msg.datapath.id)

        if ev.msg.datapath.id in self.saved_stats:
            self.prev_saved_stats[ev.msg.datapath.id] = self.saved_stats[ev.msg.datapath.id]

        self.saved_stats[ev.msg.datapath.id] = {stat.port_no: stat.rx_bytes for stat in body} 

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
        print "host {} is trying to ddos!!!".format(host)
        print "host {} is trying to ddos!!!".format(host)
        print "host {} is trying to ddos!!!".format(host)
        print "host {} is trying to ddos!!!".format(host)
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"
        print "********************************"
