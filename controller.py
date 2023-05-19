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

import rest_firewall

from dhcp import DHCPServer
from mydns import MYDNSServer
   
def form_id(id):
    if id >= 200:
        return f"h{id-200}"
    return f"s{id-100}"

class NetDevice:
    def __init__(self, owner, id):
        self.id = id
        self.owner = owner
        self.adjust = []
        self.router_table = {self: (0, self)}
    
    def get_port(self,adj_device):
        for dev,port in self.adjust:
            if adj_device is dev:
                return port
        
        print(f"WARN: cannot find port of this adj_dev: {adj_device.id}!")
        print(f"adj size: {len(self.adjust)}")
        self.print_info()
                
    def print_info(self):
        print(f"=====[Device {form_id(self.id)}]=====")
        print(f"adjust info:")
        for adj in self.adjust:
            print(f"[{form_id(self.id)}] -> {form_id(adj[0].id)} == 1")
        print(f"routing table:")
        for route in self.router_table.keys():
            print(f"[{form_id(self.id)}] -> {form_id(route.id)} == {self.router_table[route][0]} (nxt skip: {form_id(self.router_table[route][1].id)})")
        
        
    def destroy(self):
        self.adjust = None
        self.owner = None
        self.router_table = None
    
    def is_adjust(self, other_device):
        for adj_dev, d in self.adjust:
            if other_device is adj_dev:
                return True
        return False
    
    def add_adjust(self, other_device, port):
        self.adjust.append((other_device,port))
        self.update_from_adj(other_device,1)
        
    #update the table by giving an adjust device and the distance.
    def update_from_adj(self, adj_dev, adj_distance = 1):
        
        if not self.is_adjust(adj_dev):
            return

        updated = False
        for key in adj_dev.router_table:
            if key in self.router_table.keys():
                if self.router_table[key][0] > adj_dev.router_table[key][0]+adj_distance:
                    self.router_table[key] = (adj_dev.router_table[key][0]+adj_distance, adj_dev)
                    updated = True
            else: 
                self.router_table[key] = (adj_dev.router_table[key][0]+adj_distance, adj_dev)
                updated = True
                
        if updated:
            for dev in self.adjust:
                dev[0].update_from_adj(self,1)
            
# router_entry: destination: (distance, next_skip)
class SwitchDevice(NetDevice):
    
    def __init__(self, owner, id):
        super().__init__(owner, 100+id)
    
    def destroy(self):
        datapath = self.owner.dp
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        for dst in self.router_table.keys():
            if dst.is_host():

                dst_addr = dst.MAC_addr # target host
                match = ofp_parser.OFPMatch(dl_dst = dst_addr)
                
                req = ofp_parser.OFPFlowMod(datapath=datapath, command=ofp.OFPFC_DELETE, buffer_id=0xffffffff,
                                            out_port=ofp.OFPP_NONE, match=match)
                datapath.send_msg(req)
        pass
        super().destroy();
        
        
    def has_port(self, port):
        for sport in self.owner.ports:
            if sport.dpid == port.dpid and sport.port_no == port.port_no:
                return True
        return False
    
    def is_host(self):
        return False
    
        
    def commit(self):
        datapath = self.owner.dp
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        # boardcast(default) setting: just only send it to controller~
        if True:
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
            
            # match = ofp_parser.OFPMatch(dl_dst = 'ff:ff:ff:ff:ff:ff')
            # req = ofp_parser.OFPFlowMod(datapath=datapath, command=ofp.OFPFC_ADD, buffer_id=0xffffffff,
            #                                 priority=9999, flags=0, match=match, out_port = 0, actions=actions)
            # datapath.send_msg(req)
            
            match = ofp_parser.OFPMatch()
            req = ofp_parser.OFPFlowMod(datapath=datapath, command=ofp.OFPFC_ADD, buffer_id=0xffffffff,
                                            priority=1000, flags=0, match=match, out_port = 0, actions=actions)
            datapath.send_msg(req)
        
        # flow setting: send to next flow and controller~
        for dst in self.router_table.keys():
            if dst.is_host():
                next_skip = self.router_table[dst][1]
                next_skip_port = self.get_port(next_skip).port_no # port of next skip
                dst_addr = dst.MAC_addr # target host
                actions = [ofp_parser.OFPActionOutput(next_skip_port)]
                match = ofp_parser.OFPMatch(dl_dst = dst_addr)
                
                req = ofp_parser.OFPFlowMod(datapath=datapath, command=ofp.OFPFC_ADD, buffer_id=0xffffffff,
                                            priority=2333, flags=0, match=match, out_port = next_skip_port, actions=actions)
                datapath.send_msg(req)
                # print(f"Flow commit for {form_id(self.id)}: {dst_addr}({form_id(dst.id)}) -> port{next_skip_port}({form_id(next_skip.id)})")
        pass
    

class HostDevice(NetDevice):
    
    
    def __init__(self, owner, id):
        super().__init__(owner, 200+id)
        self.MAC_addr = f'00:00:00:00:00:0{id}'
        
    def is_host(self):
        return True
    
    def has_port(self, port):
        for sport in [self.owner.port]:
            if sport.dpid == port.dpid and sport.port_no == port.port_no:
                return True
        return False
 

class ControllerApp(rest_firewall.RestFirewallAPI):
    
    #totaly update when topology changes
    switch_dev = []
    host_dev = []
    
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def print_debug_message(self):
        for dev in self.switch_dev:
            dev.print_info()
        for dev in self.host_dev:
            dev.print_info()
            
    def topology_update(self):
        
        # clean the old topology
        for dev in self.switch_dev:
            dev.destroy()
        self.switch_dev.clear()
        
        for dev in self.host_dev:
            dev.destroy()
        self.host_dev.clear()
        
        print(f"updating topology.")
        # translate switches to net point
        for id,switch in enumerate(self.send_request(event.EventSwitchRequest(None)).switches):
            nd = SwitchDevice(switch,id+1)
            self.switch_dev.append(nd)
        
        # translate hosts to net point
        for id,host in enumerate(self.send_request(event.EventHostRequest(None)).hosts):
            nd = HostDevice(host,id+1)
            self.host_dev.append(nd)
            for sw_dev in self.switch_dev:
                if sw_dev.has_port(host.port):
                    sw_dev.add_adjust(nd,host.port)
                    nd.add_adjust(sw_dev,host.port)
                    
            
            
        # translate link to edge in map
        for link in self.send_request(event.EventLinkRequest(None)).links:
            # print(f"link info: {link.src.dpid},{link.src.port_no}({link.src.hw_addr}) <-> {link.dst.dpid},{link.dst.port_no}({link.dst.hw_addr})")
            src,dst = None,None
            for dev in self.switch_dev:
                if dev.has_port(link.src):
                    src = dev
                if dev.has_port(link.dst):
                    dst = dev
            src.add_adjust(dst,link.src)

        for switch in self.switch_dev:
            switch.commit()
            
        # self.print_debug_message()
            
    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        self.arp_table = {
            "10.0.0.0": "00:00:00:00:00:00",
            # "10.0.0.2": "00:00:00:00:00:02",
            # "10.0.0.3": "00:00:00:00:00:03"
        }
        MYDNSServer.init_db()

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev): 
        print("new switches added.")
        self.topology_update()
        
    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print("switches deleted.")
        self.topology_update()
        
    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print("new host added.")
        self.topology_update()
        # self.print_debug_message()
        
    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print("new link added.")
        self.topology_update()
        
    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print("link deleted.")
        self.topology_update()

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        print("port modified.")
        self.topology_update()

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
            inPort = msg.in_port
            
            if pkt.get_protocols(dhcp.dhcp): 
                DHCPServer.handle_dhcp(datapath, inPort, pkt)  
                
            elif pkt.get_protocols(arp.arp):
                arp_pkt = pkt.get_protocol(arp.arp)
                
                if (arp_pkt.src_ip == arp_pkt.dst_ip): # arping, update arp table
                    self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
                else:
                    print(f'arp from {arp_pkt.src_ip} to {arp_pkt.dst_ip} mac from {arp_pkt.src_mac} to {arp_pkt.dst_mac}')
                
                    self.handle_arp(datapath, pkt.get_protocol(ethernet.ethernet), arp_pkt, inPort)              
                    
            elif pkt.get_protocols(udp.udp):
                print(f'udp handled:',pkt.get_protocol(udp.udp).dst_port)
                if pkt.get_protocol(udp.udp).dst_port == 53:
                    print(f'dns handled.')
                    MYDNSServer.handle_dns(datapath, pkt, inPort)
            else:
                if pkt.get_protocols(ipv4.ipv4):
                    eth_pkt = pkt.get_protocol(ipv4.ipv4)
                    print(f"unsupported protocols. ({eth_pkt.src}->{eth_pkt.dst})")
                
        except Exception as e:
            self.logger.error(e)
    


