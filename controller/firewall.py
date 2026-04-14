from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp

class BroskiFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BroskiFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        print("[+] ryu controller initialized broski. firewall is active.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table miss flow entry. basically what to do if the switch is clueless
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore ipv6 stuff bruh, we dont need that noise
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # learn the mac address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        # firewall logic starts here broski
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ipv4_pkt and tcp_pkt:
            # check if it's hitting our c++ server port
            if tcp_pkt.dst_port == 8080:

                # malicious homie h1 (10.0.0.1) trying to send files
                if ipv4_pkt.src == '10.0.0.1':
                    print(f"[!] FIREWALL ALERT: blocked tcp traffic from {ipv4_pkt.src} to {ipv4_pkt.dst} on port 8080 broski")

                    # install a hard drop rule in the switch so controller doesn't get spammed
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                            ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst,
                                            tcp_dst=8080)
                    actions = []  # empty actions array means DROP the packet damn
                    self.add_flow(datapath, 100, match, actions)
                    return  # kill the execution right here

                # trusted homie h3 (10.0.0.3) trying to send files
                elif ipv4_pkt.src == '10.0.0.3':
                    print(f"[+] FIREWALL ALLOWED: trusted traffic from {ipv4_pkt.src} to {ipv4_pkt.dst} on port 8080")

        # standard l2 forwarding for everything else (arp, pings, trusted tcp)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)