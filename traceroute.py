import sys
import os
import scapy.all as sp

#Esto lo hice viendo como changos se usaba el scapy, haganle lo que quieran

req = sp.IP(dst="216.58.202.4")/sp.ICMP()

answers = []

for i in range(0,9):
	req.ttl = i+1
	answers.append(sp.sr(req))
	answers[i][0].show()