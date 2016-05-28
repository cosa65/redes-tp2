import sys
import os
import scapy.all as sp

#Esto lo hice viendo como changos se usaba el scapy, haganle lo que quieran, acuerdense de correr con sudo

# Se corre asi: sudo python traceroute.py <IP a pingear> <maximo ttl de mis paquetes>

#################Defines###############
myanswers=0			# Estas cosas estan para que se entienda mas que estas haciendo
myreplies=1			# cuando accedes a los elementos de replies[]
myreplypackage=1 	#
#######################################

req = sp.IP(dst="216.58.202.4")/sp.ICMP()
timerange = 10								#default



if len(sys.argv) == 2:						#setear manualmente IP destino
	req.dst = sys.argv[1]				
if len(sys.argv) == 3:						#setear manualmente cantidad de echo requests sucesivos a mandar
	timerange = int(sys.argv[2])


replies = []

for i in range(1,timerange+1):
	req.ttl = i

	replies.append((sp.sr(req, timeout = 10, verbose = 0))[0])
	
	recpack = replies[i-1][myanswers][myreplypackage]

	if (recpack.type == 11):
		print("Time Exceeded from:")
	elif (recpack.type == 0):
		print("Echo Reply from:")

	print(recpack.src)