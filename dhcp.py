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
class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8' # don't modify, just for the dns entry
    
    #test_ins124
    start_ip = '192.168.1.5' 
    end_ip = '192.168.1.11' 
    netmask = '255.255.255.0'
     
    #test_ins3 modify them
    # start_ip = '192.168.1.5' 
    # end_ip = '192.168.1.11' 
    # netmask = '255.255.255.0' 

    
    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.

def dhcp_server_ip_cal(start_ip,end_ip,netmask):
    netmasks=netmask.split(".")
    pre_length=0
    for i in netmasks:
        pre_length+=str(bin(int(i))).count("1")
    #start_ip to bin
    start_ips=start_ip.split(".")
    bin_start_ip=''
    for i in start_ips:
        bin_start_ip+=str(bin(int(i)))[2:].rjust(8,"0")
    bin_dhcp_host=bin_start_ip[:pre_length]
    hdcp_host_array=[]
    st=0
    count=0
    while pre_length>=8:
        hdcp_host_array.append(str(int(bin_start_ip[st:st+8],2)))
        st+=8
        pre_length-=8
        count+=1
    if pre_length>0:
        tempt=bin_start_ip[st:st+pre_length]
        tempt=tempt.ljust(8,"0")
        hdcp_host_array.append(str(int(tempt,2)))
        count+=1
    while count<4:
        hdcp_host_array.append(str(0))
        count+=1
    hdcp_host_array[3]=str(int(hdcp_host_array[3])+1)
    dhcp_server_ip=''
    for i in range(len(hdcp_host_array)-1):
        dhcp_server_ip+=hdcp_host_array[i]+"."
    dhcp_server_ip+=hdcp_host_array[3]
    return dhcp_server_ip

def bin2str(bin_ip):
    str_ip=str(bin_ip)[2:]
    result=''
    st=0
    for i in range(3):
        result+=str(int(str_ip[st:st+8],2))+"."
        st+=8
    result+=str(int(str_ip[24:],2))
    return result

def cons_ip_mac_pool(start_ip,end_ip):
    start_ips=start_ip.split(".")
    bin_start_ip=''
    for i in start_ips:
        bin_start_ip+=str(bin(int(i)))[2:].rjust(8,"0")
    end_ips=end_ip.split(".")
    bin_end_ip=''
    for i in end_ips:
        bin_end_ip+=str(bin(int(i)))[2:].rjust(8,"0")
    bin_start_ip=bin(int(bin_start_ip,2))
    bin_end_ip=bin(int(bin_end_ip,2))
    ip_mac_pool={}
    bin_current_ip=bin_start_ip
    while int(bin_current_ip,2)<=int(bin_end_ip,2):
        str_current_ip=bin2str(bin_current_ip)
        ip_mac_pool[str_current_ip]=''
        bin_current_ip=bin(int(bin_current_ip,2)+1)
    return ip_mac_pool

def akc_byte2str(byte_ip):
    result=str(ipaddress.IPv4Address(byte_ip))
    return result

def return_nak(pkt):
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

def return_ack(pkt,cur_ip):
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

def return_leasetime_ack(pkt,cur_ip):
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

def return_icmp(src_ip,req_ip):
    icmp_pkt = packet.Packet()
    icmp_pkt.add_protocol(
        ipv4.ipv4(dst=req_ip, src=src_ip))
    icmp_pkt.add_protocol(icmp.icmp(type_=8, code=0, csum=0, data=b''))
    # print(f"return icmp \n content is {icmp_pkt}")
    return icmp_pkt



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
    #时间太短会出问题50可以
    release_time='00000050'
    
    @classmethod
    def assemble_offer(cls,pkt, datapath,port):
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
            if DHCPServer.ip_mac_pool[key]=='':
                cur_ip=key
                DHCPServer.ip_mac_pool[key]=disc_eth.src
                DHCPServer.mac_ip_pool[disc_eth.src]=key
                break
 
        if cur_ip=='':
            # print(f'null offer')
            return 'null'
        else:
            offer_pkt.add_protocol(dhcp.dhcp(op=2, 
                                            chaddr=disc_eth.src,
                                            boot_file=disc.boot_file,
                                            yiaddr=cur_ip,
                                            xid=disc.xid,
                                            options =disc.options,
                                            flags=disc.flags
            ))

            
            # print(f'assemble offer send \n content is {offer_pkt}')
            return offer_pkt

    @classmethod
    def assemble_ack(cls, pkt, datapath):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req = pkt.get_protocol(dhcp.dhcp)
        cur_ip=''
        for opt in req.options.option_list:
            if opt.tag == 50 :
                # print(opt)
                # print(opt.value)
                cur_ip=akc_byte2str(opt.value)
        if DHCPServer.ip_mac_pool[cur_ip]==req_eth.src:
            return return_ack(pkt,cur_ip)
        else:
            return return_nak(pkt)
    

    @classmethod
    def assemble_leasetime_ack(cls, pkt, datapath):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        cur_ip=''
        cur_ip=DHCPServer.mac_ip_pool[req_eth.src]
        if not cur_ip=='':
            return return_leasetime_ack(pkt,cur_ip)
        else:
            return return_nak(pkt)

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
       
        # print(f'new dhcp {dhcp_state} packet recieved \n content is: {pkt_dhcp}')
        if dhcp_state=='DHCPDISCOVER':
            offer_pkt=DHCPServer.assemble_offer(pkt,datapath,port)
            if not offer_pkt=='null':
                # print(f'offer send')
                DHCPServer._send_packet(datapath,port,offer_pkt)
            else:
                # print(f'null offer send')
                return
        elif dhcp_state=='DHCPREQUEST' and has_50:
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_ack(pkt,datapath))
            # print("ack send")
            # print("------------------------")
            # DHCPServer._send_packet(datapath,port,return_icmp('192.168.1.1','192.168.1.5'))
            # print("icmp send")
            # print("------------------------")
        elif dhcp_state=='DHCPREQUEST' and not has_50:
            DHCPServer._send_packet(datapath,port,DHCPServer.assemble_leasetime_ack(pkt,datapath))
            # print("lease time ack send")
        else:
            # print(f"receive other packet \n content is {pkt}")
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

   