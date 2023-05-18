from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp

from dnslib import DNSRecord, RR, QTYPE

class DNSServer():
    
	RRs = []
	@classmethod
	def init():
		DNSServer.RRs.append('example1.com','10.0.0.1',QTYPE.A)
		DNSServer.RRs.append('example2.com','10.0.0.2',QTYPE.A)

	@classmethod
	def append(name,value,type):
		DNSServer.RRs.append(RR(name,type,rdata=value))
  
	@classmethod
	def gen_reply(query):
		r = query.reply()
		if not query.questions:
			print("ERROR: DNS request is not questioning")
			return r
			
		for question in query.questions:
			name = str(question.get_qname())
			for RR in DNSServer.RRs:
				if RR.type == type and RR.name == name:
					r.add_answer(RR)
     
		return r

	@classmethod
	def handle_dns(datapath, pkt, port):
		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		pkt_udp = pkt.get_protocol(udp.udp)

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		query = DNSRecord.parse(pkt.protocols[-1])
		if query.questions:
			ip_src = pkt_ipv4.dst
			ip_dst = pkt_ipv4.src
			sport = 53
			dport = pkt_udp.src_port
			
			response = packet.Packet()
			response.add_protocol(ethernet.ethernet(dst=pkt_ethernet.src,src=pkt_ethernet.dst))
			response.add_protocol(ipv4.ipv4(st=ip_dst,src=ip_src))
			response.add_protocol(udp.udp(sport=sport,dport=dport))

			reply_payload = DNSServer.gen_reply(query).pack()
			response.add_protocol(reply_payload)
	
			actions = [parser.OFPActionOutput(port=port)]
			out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
                             in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=response.serialize().data)
			datapath.send_msg(out)
			print("Send DNS Response")

   