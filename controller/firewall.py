from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import tcp
from os_ken.lib.packet import icmp

class BroskiFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BroskiFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        print("[+] OS-Ken Multi-Layer Firewall online broski. Let's catch some strays.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # if the dumb switch doesn't know what to do, send it up to the boss
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

        # ignore the useless background network chatter
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # LAYER 2: keeping track of where these hosts actually live
        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Ensure we only log and inspect actual IPv4 network traffic
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            print("\n" + "="*65)
            print(f"[*] INCOMING PACKET DETECTED")
            
            # --------------------------------------------------------
            # 1. LAYER 2 CHECK (Hardware/MAC) -> Targets h1
            # --------------------------------------------------------
            print(f"  -> [L2 MAC] Src: {src_mac} | Dst: {dst_mac}")
            
            if src_mac == '00:00:00:00:00:01': # h1's literal MAC address
                print(f"[!] BLOCKED AT LAYER 2: h1 MAC address is blacklisted broski.")
                print("="*65)
                match = parser.OFPMatch(eth_src=src_mac)
                self.add_flow(datapath, 100, match, []) # empty actions = drop
                return

            # --------------------------------------------------------
            # 2. LAYER 3 CHECK (Network/Ping) -> Targets h2
            # --------------------------------------------------------
            print(f"  -> [L3 IP]  Src: {src_ip:<15} | Dst: {dst_ip}")
            
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and src_ip == '10.0.0.2': # h2 trying to ping
                print(f"[!] BLOCKED AT LAYER 3: h2 ICMP/Ping traffic explicitly denied.")
                print("="*65)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ip_proto=1) # protocol 1 is ICMP
                self.add_flow(datapath, 100, match, [])
                return

            # --------------------------------------------------------
            # 3. LAYER 4 CHECK (Transport/Port) -> Targets h3
            # --------------------------------------------------------
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
                print(f"  -> [L4 TCP] Target Port: {dst_port}")
                
                if src_ip == '10.0.0.3': # h3 trying to hit ports
                    if dst_port == 8080:
                        print(f"[!] BLOCKED AT LAYER 4: h3 trying to hit the C++ payload on 8080.")
                        print("="*65)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ip_proto=6, tcp_dst=dst_port)
                        self.add_flow(datapath, 100, match, []) # banish to Madhya Pradesh
                        return
                        
                    elif dst_port == 22:
                        print(f"[!] BLOCKED AT LAYER 4: h3 attempting SSH/netcat on Port 22. Denied.")
                        print("="*65)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ip_proto=6, tcp_dst=22)
                        self.add_flow(datapath, 100, match, [])
                        return

            # --------------------------------------------------------
            # 4. TRUSTED HOST -> Targets h4
            # --------------------------------------------------------
            print(f"[+] ALL CHECKS PASSED: Traffic is clean. Let it through.")
            print("="*65)

        # if we ain't dropping it, tell the switch to remember the route
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
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