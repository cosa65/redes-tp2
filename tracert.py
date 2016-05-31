#!/usr/bin/python3
# NOTES: run as root. To install dependencies: sudo pip3 install scapy-python3
import scapy.all as sp
import numpy as np
import time


# TODO: tomar parametros por consola para hacer esta chota
host = "google.com"
scan = "icmp" # ICMP, UDP or TCP
accuracy = 10 # Number of measures we want per TTL
retries_per_attempt = 3 # Maximum number of times to attempt to measure
packet_timeout = 0.25 # In fractional seconds
max_ttl = 50 # Maximum route length

packets = sp.IP(
	ttl=(1, max_ttl),
	dst=sp.Net(host))

if scan == 'icmp':
	packets = packets/sp.ICMP()
elif scan == 'tcp':
	packets = packets/sp.TCP(dport=80, flags='S')
elif scan == 'udp':
	packets = packets/sp.UDP()/sp.DNS(qd=sp.DNSQR(qname='whatever.com'))
else:
	raise Exception('Unknown scan type')

trace = []

for packet in packets:
	packet_start = time.perf_counter()

	answers = []
	finished = False
	sent = 0
	recv = 0

	for attempt in range(accuracy):
		rtt = received = None
		success = False

		for retry in range(retries_per_attempt):
			rtt = time.perf_counter()
			received = sp.sr1(packet, timeout=packet_timeout, verbose = 0)
			rtt = time.perf_counter() - rtt
			sent += 1

			if received is not None:
				recv += 1
				success = True
				break

		if success:
			answers.append((rtt, received))

			# If this is the last node in the path, just stop the traceroute
			if received.src == packet.dst:
				finished = True
		else:
			# TODO: this particular attempt timed out every time
			pass

	packet_end = time.perf_counter()

	current = {
		'ttl': packet.ttl,
		'inaccurate': len(answers) < accuracy,
		'time': packet_end - packet_start,
		'sent': sent,
		'received': recv,
		'failed': len(answers) == 0,
		# TODO: convert these two into json or something like that
		'packet': packet,
		'answers': answers
	}

	if not current['failed']:
		rtts = [answer[0] for answer in answers]

		current.update({
			'ip': answers[0][1].src,
			'rtt_avg': np.average(rtts),
			'rtt_stdev': np.std(rtts),
			'failed': False
		})

		print(current['ttl'], current['ip'], current['rtt_avg'])
	else:
		print(current['ttl'], '*')

	trace.append(current)

	if finished:
		break

# TODO: meter el objeto trace en mongodb, asi lo levantamos sabrosamente con tableau 

print(trace)