from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from dhcp import DHCPServer

# router_entry: destination: (distance, next_skip)
class NetDevice:
    
    def __init__(self, owner, id):
        self.id = id
        self.owner = owner
        self.router_table = {owner: (0,None)}
        self.adjust = []
        
    def destroy(self):
        self.router_table = None
        self.adjust = None
        self.owner = None
        
    def print_info(self):
        print(f"=====[s{self.id}]=====")
        print(f"adjust info:")
        for adj in self.adjust:
            print(f"[s{self.id}] -> s{adj.id} == 1")
        print(f"routing table:")
        for route in self.router_table.keys:
            print(f"[s{self.id}] -> s{route.id} == {self.router_table[route][0]} (nxt skip: s{self.router_table[route][1].id})")
            
    def is_src(self, link):
        for port in self.owner.ports:
            if link.src.dpid == port.dpid and link.src.port_no == port.port_no:
                return True
        return False
    
    def is_dst(self, link):
        for port in self.owner.ports:
            if link.dst.dpid == port.dpid and link.dst.port_no == port.port_no:
                return True
        return False
    
    def add_adjust(self, other_device):
        self.adjust.append(other_device)

    def update_adjust(self):
        for adj in self.adjust:
            adj.update_from_adj(self, 1)
    
    #update the table by giving an adjust device and the distance.
    def update_from_adj(self, adj_dev, adj_distance = 1):
        updated = False
        for key in adj_dev.router_table:
            if key in self.router_table.keys:
                if self.router_table[key][0] > adj_distance[key][0]+adj_distance:
                    self.router_table[key] = (adj_distance[key][0]+adj_distance, adj_dev)
                    updated = True
            else: 
                self.router_table[key] = (adj_distance[key][0]+adj_distance, adj_dev)
                updated = True
                
        if updated:
            self.update_adjust()
            
class ControllerApp(app_manager.RyuApp):
    
    #record the original danshielements in Ryu
    #permanently saved
    switch_devices = []
    links = []
    
    #totaly update when topology changes
    network_point = []
    topology = []
    
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    def topology_update(self):
        
        # clean the old topology
        for dev in self.network_point:
            dev.destroy()
        self.network_point.clear()
        print("rebuilding topology")
        
        # translate switches to net point
        for id,switch in enumerate(self.send_request(event.EventSwitchRequest(None)).switches):
            nd = NetDevice(switch,id)
            self.network_point.append(nd)
        
        # translate link to edge in map
        for link in self.send_request(event.EventLinkRequest(None)).links:
            src,dst = None,None
            for dev in self.network_point:
                if dev.is_src(link):
                    src = dev
                if dev.is_dst(link):
                    dst = dev
            src.add_adjust(dst)
        
        #print debug message
        for dev in self.network_point:
            dev.print_info()
        
    
    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        self.arp_table = {
            # "10.0.0.1": "00:00:00:00:00:01",
            # "10.0.0.2": "00:00:00:00:00:02",
            # "10.0.0.3": "00:00:00:00:00:03"
        }

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        
        print("new switches added: ",ev)
        """
        Event handler indicating a switch has come online.
        """
        
    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print("switches deleted: ",ev)
        """
        Event handler indicating a switch has been removed
        """

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print("new host added: ",ev)
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """ 
        # TODO:  Update network topology and flow rules
        
        
    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print("new link added: ",ev)
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules
        
    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print("link deleted: ",ev)
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules


    def handle_arp(self, datapath, eth, arp_pkt, in_port):
        r = self.arp_table.get(arp_pkt.dst_ip)
        if r:
            arp_resp = packet.Packet()
            arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                  dst=eth.src, src=r))
            arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                  src_mac=r, src_ip=arp_pkt.dst_ip,
                                  dst_mac=arp_pkt.src_mac,
                                  dst_ip=arp_pkt.src_ip))
            arp_resp.serialize()
            parser = datapath.ofproto_parser  
            actions = [parser.OFPActionOutput(in_port)]
            ofproto = datapath.ofproto
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            inPort = msg.in_port
            if not pkt_dhcp:
                if pkt.get_protocols(arp.arp):
                    arp_pkt = pkt.get_protocol(arp.arp)
                    
                    if (arp_pkt.src_ip == arp_pkt.dst_ip): # arping, update arp table
                        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
                    else:
                        self.handle_arp(datapath, pkt.get_protocol(ethernet.ethernet), arp_pkt, inPort)
                    
                    self.topology_update()
                    self.logger.info(f'arp request from {arp_pkt.src_ip} to {arp_pkt.dst_ip} mac from {arp_pkt.src_mac} to {arp_pkt.dst_mac}')
                pass
            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)      
            return 
        except Exception as e:
            self.logger.error(e)
    
