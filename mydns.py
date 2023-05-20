from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from dnslib import DNSRecord, RR, QTYPE, A

class MYDNSServer():
	RRs = []
 
	@classmethod
	def init_db(cls):
		MYDNSServer.append('example1.com',A('10.0.0.1'),QTYPE.A)
		MYDNSServer.append('example2.com',A('10.0.0.2'),QTYPE.A)
		print('DNS server init success.')

	@classmethod
	def append(cls, qname,value,type):
		MYDNSServer.RRs.append(RR(qname,type,rdata=value,ttl=3))

	@classmethod
	def gen_reply(cls, query):

		r = query.reply()
  
		if not query.questions:
			print("ERROR: DNS request is not questioning")
			return r

		for question in query.questions:
			name = str(question.get_qname())
			type = question.qtype

			for RR in MYDNSServer.RRs:
				if RR.rtype == type and RR.rname == name:
					print("add answer success.")
					r.add_answer(RR)

		return r

	@classmethod
	def handle_dns(cls, datapath, pkt, port):
		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		pkt_udp = pkt.get_protocol(udp.udp)

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser		

		query = DNSRecord.parse(pkt.protocols[-1])

		if query.questions:

			pkt_ethernet_resp = pkt_ethernet
			pkt_ethernet_resp.src, pkt_ethernet_resp.dst = pkt_ethernet_resp.dst, pkt_ethernet_resp.src
			
			pkt_ipv4_resp = pkt_ipv4
			pkt_ipv4_resp.src, pkt_ipv4_resp.dst = pkt_ipv4_resp.dst, pkt_ipv4_resp.src
			pkt_ipv4_resp.total_length = 0 #automatically-calculate

			response = packet.Packet()
			response.add_protocol(pkt_ethernet_resp)
			response.add_protocol(pkt_ipv4_resp)
			response.add_protocol(udp.udp(src_port=53,dst_port=pkt_udp.src_port))
			reply_payload = MYDNSServer.gen_reply(query).pack()
			response.add_protocol(reply_payload)
			response.serialize()

			actions = [parser.OFPActionOutput(port=port)]
			out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
							in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=response.data)
			datapath.send_msg(out)
			print("Send DNS Response")

if __name__ == '__main__':
	MYDNSServer.init_db()