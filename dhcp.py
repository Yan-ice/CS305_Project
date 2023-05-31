from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet import icmp
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
import binascii
import struct
import ipaddress
from ipaddress import ip_address
from time import sleep
class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8' # don't modify, just for the dns entry
    
    #test_ins124
    start_ip = '192.168.1.2' 
    end_ip = '192.168.1.10' 
    netmask = '255.255.255.0'
     
    #modify them
    # start_ip = '10.26.133.163' 
    # end_ip = '10.26.144.4' 
    # netmask = '255.252.0.0' 

    release_time='00001000'
    
    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.

def dhcp_server_ip_cal(start_ip,end_ip,netmask):
    pre_length=sum([bin(int(i)).count('1') for i in netmask.split('.')])
    ip_net = start_ip+"/"+str(pre_length)
    net = ipaddress.ip_network(ip_net, strict=False)
    return str([x for x in net.hosts()][0])

def cons_ip_mac_pool(start, end):
    start = ip_address(start)
    end = ip_address(end)
    result = {}
    while start <= end:
        result[str(start)]=''
        start += 1
    return result

def akc_byte2str(byte_ip):
    result=str(ipaddress.IPv4Address(byte_ip))
    return result

def construct_offer(pkt,cur_ip):
    disc_eth = pkt.get_protocol(ethernet.ethernet)
    disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
    disc_udp = pkt.get_protocol(udp.udp)
    disc = pkt.get_protocol(dhcp.dhcp)
    disc.options.option_list.remove(
        next(opt for opt in disc.options.option_list if opt.tag == 55))
    disc.options.option_list.remove(
        next(opt for opt in disc.options.option_list if opt.tag == 53))
    disc.options.option_list.remove(
        next(opt for opt in disc.options. option_list if opt.tag == 12))
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
    offer_pkt.add_protocol(dhcp.dhcp(op=2, 
                                            chaddr=disc_eth.src,
                                            boot_file=disc.boot_file,
                                            yiaddr=cur_ip,
                                            xid=disc.xid,
                                            options =disc.options,
                                            flags=disc.flags
            ))
    return offer_pkt


def construct_nak(pkt):
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
        0, dhcp.option(tag=53, value=binascii.a2b_hex('06')))
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
    nak_pkt = packet.Packet()
    nak_pkt.add_protocol(ethernet.ethernet(
        ethertype=req_eth.ethertype, dst=req_eth.src, src=DHCPServer.hardware_addr))
    nak_pkt.add_protocol(
        ipv4.ipv4(dst=req_ipv4.dst, src=DHCPServer.dhcp_server, proto=req_ipv4.proto))
    nak_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
    nak_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                    siaddr=DHCPServer.dhcp_server,
                                    boot_file=req.boot_file,
                                    yiaddr='0',
                                    ciaddr='0',
                                    xid=req.xid,
                                    options=req.options,
                                    flags=req.flags))
    # print(f'return nak \n content is {nak_pkt}')
    return nak_pkt

def construct_ack(pkt,cur_ip):
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
    ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                    siaddr=DHCPServer.dhcp_server,
                                    boot_file=req.boot_file,
                                    yiaddr=cur_ip,
                                    ciaddr=req.ciaddr,
                                    xid=req.xid,
                                    options=req.options,
                                    flags=req.flags))
    # print(f'return ack \n content is {ack_pkt}')
    return ack_pkt

def construct_leasetime_ack(pkt,cur_ip):
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
        ipv4.ipv4(dst=req_ipv4.src, src=DHCPServer.dhcp_server, proto=req_ipv4.proto))
    ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
    ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                    siaddr=DHCPServer.dhcp_server,
                                    boot_file=req.boot_file,
                                    yiaddr=cur_ip,
                                    ciaddr=req.ciaddr,
                                    xid=req.xid,
                                    options=req.options,
                                    flags=req.flags))
    # print(f'return lease time ack \n content is {ack_pkt}')
    return ack_pkt

def send_icmp(pkt,src_ip,req_ip,datapath,port):
    print("========================")
    req_ip='192.168.1.5' 
    disc_eth = pkt.get_protocol(ethernet.ethernet)
    disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
    print("========================")
    icmp_pkt = packet.Packet()
    icmp_pkt.add_protocol(ethernet.ethernet(
        ethertype=disc_eth.ethertype, dst='00:00:00:00:00:01',src=DHCPServer.hardware_addr))
    print("========================")
    icmp_pkt.add_protocol(
        ipv4.ipv4(dst=req_ip, src=src_ip, proto=disc_ipv4.proto))
    icmp_pkt.add_protocol(icmp.icmp(type_=8, code=0, csum=0, data=b''))
    print("========================")
    DHCPServer._send_packet(datapath,port,icmp_pkt)
    print(f"send icmp \n content is {icmp_pkt}")
    return icmp_pkt


def ip_detection():
    print(DHCPServer.arp_table)


def find_valid_ip(pkt):
    disc_eth = pkt.get_protocol(ethernet.ethernet)
    cur_ip=''
    if disc_eth.src in DHCPServer.mac_ip_pool:
        cur_ip=DHCPServer.mac_ip_pool[disc_eth.src]
    else:
        for key in DHCPServer.ip_mac_pool:
            if DHCPServer.ip_mac_pool[key]=='':
                cur_ip=key
                DHCPServer.ip_mac_pool[key]=disc_eth.src
                DHCPServer.mac_ip_pool[disc_eth.src]=key
                break
    return cur_ip

class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    ip_mac_pool=cons_ip_mac_pool(start_ip,end_ip)
    mac_ip_pool={}
    dns = Config.dns
    bin_netmask = addrconv.ipv4.text_to_bin(netmask)
    dhcp_server = dhcp_server_ip_cal(start_ip,end_ip,netmask)
    bin_server = addrconv.ipv4.text_to_bin(dhcp_server)
    bin_dns = addrconv.ipv4.text_to_bin(dns)
    bin_hostname = bytes("mininet-vm", 'utf-8')
    bin_hardware_addr=addrconv.mac.text_to_bin(hardware_addr)
    bin_dhcp_server=addrconv.ipv4.text_to_bin(dhcp_server)
    release_time= Config.release_time
    arp_table={}
    
    @classmethod
    def update_ip_pool(cls,pkt):
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        DHCPServer.ip_mac_pool[disc_ipv4.src]=disc_eth.src
        DHCPServer.mac_ip_pool[disc_eth.src]=disc_ipv4.src
        print("icmp receive and update pool")

    @classmethod
    def assemble_offer(cls,pkt, datapath,port):
        #ip allocation detection
        # cur_ip=find_valid_ip(pkt)
        # ip_detection()
        send_icmp(pkt,DHCPServer.dhcp_server,'192.168.1.3',datapath,port)
        # sleep(2)
        cur_ip=find_valid_ip(pkt)
        #
        if cur_ip=='':
            return 'null'
        else:
            return construct_offer(pkt,cur_ip)
            

    @classmethod
    def assemble_ack(cls, pkt, datapath):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req = pkt.get_protocol(dhcp.dhcp)
        cur_ip=''
        for opt in req.options.option_list:
            if opt.tag == 50 :
                cur_ip=akc_byte2str(opt.value)
        if DHCPServer.ip_mac_pool[cur_ip]==req_eth.src:
            return construct_ack(pkt,cur_ip)
        else:
            return construct_nak(pkt)
    

    @classmethod
    def assemble_leasetime_ack(cls, pkt, datapath):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        cur_ip=''
        if req_eth.src in DHCPServer.mac_ip_pool:
            cur_ip=DHCPServer.mac_ip_pool[req_eth.src]
            print("lease time ack")
            return construct_leasetime_ack(pkt,cur_ip)
        else:
            print("lease time nak")
            return construct_nak(pkt)

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
        if dhcp_state=='DHCPDISCOVER':
            offer_pkt=DHCPServer.assemble_offer(pkt,datapath,port)
            if not offer_pkt=='null':
                DHCPServer._send_packet(datapath,port,offer_pkt)
            else:
                print(f'null offer send')
                return
        elif dhcp_state=='DHCPREQUEST' and has_50:
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_ack(pkt,datapath))
        elif dhcp_state=='DHCPREQUEST' and not has_50:
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_leasetime_ack(pkt,datapath))    
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

   