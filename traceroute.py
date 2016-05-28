import sys
import os
import scapy.all as sp
import time
from datetime import datetime

# Se corre asi: "sudo python traceroute.py <IP destino> <maximo ttl de mis paquetes>"

repets = 3			#cantidad de veces que queres que envia paquete de igual ttl (para promediar)
verbose = 1			#lo ves en la terminal o no

#################Defines###############
myanswers=0			# Estas cosas estan para que se entienda mas que estas haciendo
myreplies=1			# cuando accedes a los elementos de replies[]
myreplypackage=1 	#
#######################################

req = sp.IP(dst="216.58.202.4")/sp.ICMP()
timerange = 10								#default

jmps=0

if len(sys.argv) >= 2:						#setear manualmente IP destino
	req.dst = sys.argv[1]				
if len(sys.argv) == 3:						#setear manualmente cantidad de echo requests sucesivos a mandar
	timerange = int(sys.argv[2])

times = []
replies = []

for i in range(1,timerange+1):
	req.ttl = i
	times.append(0);

	
	for j in range(0,repets):
		start = datetime.now()
		answer = sp.sr(req, timeout = 10, verbose = 0)
		end = datetime.now()
		times[i-1] += end.microsecond - start.microsecond + ((end.second - start.second) * 1000000)
	times[i-1] = times[i-1]/repets

	
	replies.append(answer[0])
	recpack = replies[i-1][myanswers][myreplypackage]


	if(recpack.type == 0):
		jmps = i


######################ESTO SI LO QUERES EN LA TERMINAL#####
	if(verbose):
		if (recpack.type == 11):
			print("Time Exceeded from:")
		elif (recpack.type == 0):
			print("Echo Reply from:")

		print(recpack.src)

		print(" RTT: ")
		print(str(times[i-1]))
		print("\n")
###########################################################

file = open("test/test.txt", "w")

for i in range(0, timerange):

	recpack = replies[i][myanswers][myreplypackage]
	if (recpack.type == 11):
		file.write("Time Exceeded from: ")
	elif (recpack.type == 0):
		file.write("Echo Reply from: ")

	file.write(recpack.src)

	file.write(" RTT: ")
	file.write(str(times[i]))
	file.write("\n")


file.write("jumps hasta llegar: ")
file.write(str(jmps))

file.close()