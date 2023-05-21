from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
import binascii
import struct

class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8' # don't modify, just for the dns entry
    start_ip = '192.168.1.2' # can be modified
    end_ip = '192.168.1.10' # can be modified
    netmask = '255.255.255.0' # can be modified
    
    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():

    
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip

    start_ip_num=int(start_ip[10:])
    end_ip_num=int(end_ip[10:])
    ip_start_prefix='192.168.1.'
    ip_mac_pool={}
    mac_ip_pool={}
    for i in range(start_ip_num,end_ip_num+1):
        ip_mac_pool[ip_start_prefix+str(i)]="null"

    netmask = Config.netmask
    dns = Config.dns
    bin_netmask = addrconv.ipv4.text_to_bin(netmask)
    dhcp_server = '192.168.1.1'
    bin_server = addrconv.ipv4.text_to_bin(dhcp_server)
    bin_dns = addrconv.ipv4.text_to_bin(dns)
    bin_hostname = bytes("mininet-vm", 'utf-8')
    bin_hardware_addr=addrconv.mac.text_to_bin(hardware_addr)
    bin_dhcp_server=addrconv.ipv4.text_to_bin(dhcp_server)
    #时间太短会出问题50可以
    release_time='00000050'
    
    @classmethod
    def assemble_offer(cls, pkt, datapath):
        
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 55))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 53))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 12))
        
        disc.options.option_list.insert(
            0, dhcp.option(tag=1, value=DHCPServer.bin_netmask))
        disc.options.option_list.insert(
            0, dhcp.option(tag=3, value=DHCPServer.bin_server))
        disc.options.option_list.insert(
            0, dhcp.option(tag=6, value=DHCPServer.bin_dns))
  
        disc.options.option_list.insert(
            0, dhcp.option(tag=53, value=binascii.a2b_hex('02')))
        disc.options.option_list.insert(
            0, dhcp.option(tag=54, value=DHCPServer.bin_server))
        disc.options.option_list.insert(
            0, dhcp.option(tag=15, value=DHCPServer.bin_hostname))
        disc.options.option_list.insert(
            0, dhcp.option(tag=6, value=DHCPServer.bin_dns))
        disc.options.option_list.insert(
            0, dhcp.option(tag=51, value=binascii.a2b_hex(DHCPServer.release_time)))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=disc_eth.ethertype, dst=disc_eth.src, src=DHCPServer.hardware_addr))
        offer_pkt.add_protocol(
            ipv4.ipv4(dst=disc_ipv4.dst, src=DHCPServer.dhcp_server, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))

        cur_ip=''
        for key in DHCPServer.ip_mac_pool:
          
            if DHCPServer.ip_mac_pool[key]=="null":
                cur_ip=key
                DHCPServer.ip_mac_pool[key]=disc_eth.src
                DHCPServer.mac_ip_pool[disc_eth.src]=key
                break
 

        offer_pkt.add_protocol(dhcp.dhcp(op=2, 
                                         chaddr=disc_eth.src,
                                         boot_file=disc.boot_file,
                                         yiaddr=cur_ip,
                                         xid=disc.xid,
                                         options =disc.options,
                                         flags=disc.flags
        ))


        print(f'assemble offer send \n content is {offer_pkt}')
        return offer_pkt

    @classmethod
    def assemble_ack(cls, pkt, datapath):
        

        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 55))
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 12))
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 50))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value=binascii.a2b_hex('05')))
        req.options.option_list.insert(
            0, dhcp.option(tag=1, value=DHCPServer.bin_netmask))
        req.options.option_list.insert(
            0, dhcp.option(tag=3, value=DHCPServer.bin_server))
        req.options.option_list.insert(
            0, dhcp.option(tag=15, value=DHCPServer.bin_hostname))
        req.options.option_list.insert(
            0, dhcp.option(tag=6, value=DHCPServer.bin_dns))
        req.options.option_list.insert(
            0, dhcp.option(tag=51, value=binascii.a2b_hex(DHCPServer.release_time)))
        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=DHCPServer.hardware_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=DHCPServer.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))

        cur_ip=''
        has=False
        for key in DHCPServer.ip_mac_pool:
            if DHCPServer.ip_mac_pool[key]==req_eth.src:
                cur_ip=key
                has=True
                break
        if not has:
            for key in DHCPServer.ip_mac_pool:
                if DHCPServer.ip_mac_pool[key]=="null":
                    cur_ip=key
                    DHCPServer.ip_mac_pool[key]=req_eth.src
                    DHCPServer.mac_ip_pool[req_eth.src]=key
                    break



        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=DHCPServer.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=cur_ip,
                                       ciaddr=req.ciaddr,
                                       xid=req.xid,
                                       options=req.options,
                                       flags=req.flags))
        print(f'assemble ack send \n content is {ack_pkt}')
        return ack_pkt
    @classmethod
    def assemble_ack2(cls, pkt, datapath):
        print("assemble_ack2")

        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        print("assemble_ack2")

        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 55))
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 12))
        
        print("assemble_ack2")
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value=binascii.a2b_hex('05')))
        req.options.option_list.insert(
            0, dhcp.option(tag=1, value=DHCPServer.bin_netmask))
        req.options.option_list.insert(
            0, dhcp.option(tag=3, value=DHCPServer.bin_server))
        req.options.option_list.insert(
            0, dhcp.option(tag=15, value=DHCPServer.bin_hostname))
        req.options.option_list.insert(
            0, dhcp.option(tag=6, value=DHCPServer.bin_dns))
        req.options.option_list.insert(
            0, dhcp.option(tag=51, value=binascii.a2b_hex(DHCPServer.release_time)))
        print("assemble_ack2")
        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=DHCPServer.hardware_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.src, src=DHCPServer.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        print("assemble_ack2")
        cur_ip=''
        has=False
        for key in DHCPServer.ip_mac_pool:
            if DHCPServer.ip_mac_pool[key]==req_eth.src:
                cur_ip=key
                has=True
                break
        print("assemble_ack2")
        if not has:
            for key in DHCPServer.ip_mac_pool:
                if DHCPServer.ip_mac_pool[key]=="null":
                    cur_ip=key
                    DHCPServer.ip_mac_pool[key]=req_eth.src
                    DHCPServer.mac_ip_pool[req_eth.src]=key
                    break
        print("assemble_ack2")


        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=DHCPServer.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=cur_ip,
                                       ciaddr=req.ciaddr,
                                       xid=req.xid,
                                       options=req.options,
                                       flags=req.flags))
        print("assemble_ack2")
        print(f'assemble ack send \n content is {ack_pkt}')
        return ack_pkt





    


    @classmethod
    def get_state(cls,pkt_dhcp):
        dhcp_state=ord([opt for opt in pkt_dhcp.options.option_list if opt.tag==53][0].value)
        if dhcp_state==1:
            state='DHCPDISCOVER'
        elif dhcp_state==2:
            state='DHCPOFFER'
        elif dhcp_state==3:
            state='DHCPREQUEST'
        elif dhcp_state==4:
            state='DHCPACK'
        return state

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        
        
        pkt_dhcp=pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state=DHCPServer.get_state(pkt_dhcp)
        req = pkt.get_protocol(dhcp.dhcp)
        has_50=False
        for opt in req.options.option_list:
            if opt.tag == 50:
                has_50=True
       
        print(f'new dhcp {dhcp_state} packet recieved \n content is: {pkt_dhcp}')
        if dhcp_state=='DHCPDISCOVER':
            # print("in DHCPDISCOVER")
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_offer(pkt,datapath))
        elif dhcp_state=='DHCPREQUEST' and has_50:
            # print("in DHCPREQUEST")
            # pkt=DHCPServer.assemble_ack(pkt,datapath)
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_ack(pkt,datapath))
            # print("-----------------DHCPREQUEST send")
        elif dhcp_state=='DHCPREQUEST' and not has_50:
            print("hhhhhhhhhhhhhhh")
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_ack2(pkt,datapath))
        else:
            return
    
    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

   