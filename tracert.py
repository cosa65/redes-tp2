#!/usr/bin/python3
# NOTES: run as root. To install dependencies: sudo pip3 install scapy-python3
import scapy.all as sp
import numpy as np
import time
import requests

# TODO: tomar parametros por consola para hacer esta chota
host = "google.com"
scan = "tcp" # ICMP, UDP or TCP
accuracy = 20 # Number of measures we want per TTL
retries_per_attempt = 3 # Maximum number of times to attempt to measure
packet_timeout = 0.2 # In fractional seconds
max_ttl = 50 # Maximum route length

if len(sys.argv) >= 2:
	host = sys.argv[1]              
if len(sys.argv) >= 3:
	scan = sys.argv[2]
if len(sys.argv) >= 4:
	accuracy = sys.argv[3]
if len(sys.argv) >= 5:
	retries_per_attempt = sys.argv[4]
if len(sys.argv) >= 6:
	packet_timeout = sys.argv[5]
if len(sys.argv) >= 7:
	max_ttl = sys.argv[6]

def get_geolocation_data(ip):
	request = requests.get('https://freegeoip.net/json/'+ip)
	return request.json()
	
def traceroute(host, scan='tcp', accuracy=20, max_ttl=50, retries_per_attempt=3, packet_timeout=0.2):
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

	trace = {}

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
			'all_answers': answers
		}

		if not current['failed']:
			# Classify answers by source ip
			ips = {}

			for (rtt, answer) in answers:
				try:
					ips[answer.src]
				except:
					ips[answer.src] = []

				ips[answer.src].append((rtt, answer))

			# Select ip based on the number of answers, and whichever happened last
			selected = None
			selected_ip = ''

			for ip in ips:
				if selected is None:
					selected = ips[ip]
					selected_ip = ip
				else:
					if len(selected) <= len(ips[ip]):
						selected = ips[ip]
						selected_ip = ip

			rtts = [answer[0] for answer in selected]

			current.update({
				'most_frequent_ip': selected_ip,
				'most_frequent_src_packets': selected,
				'most_frequent_rtt_avg': np.average(rtts),
				'most_frequent_rtt_stdev': np.std(rtts),
				'failed': False
			})
		else:
			# TODO: all attempts failed
			pass

		trace[current['ttl']] = current

		if finished:
			break

	return trace

def print_traceroute(trace):
	for ttl in trace:
		if trace[ttl]['failed']:
			print(ttl, '*')
		else:
			geoip = get_geolocation_data(trace[ttl]['most_frequent_ip'])
			print(ttl, trace[ttl]['most_frequent_ip'], trace[ttl]['most_frequent_rtt_avg'], geoip['country_code'], geoip['city'])

# TODO: meter el objeto trace en mongodb, asi lo levantamos sabrosamente con tableau 

print_traceroute(traceroute(host, scan, accuracy, max_ttl, retries_per_attempt, packet_timeout))