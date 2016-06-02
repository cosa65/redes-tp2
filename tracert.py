#!/usr/bin/python3
# NOTES: run as root. To install dependencies: sudo pip3 install scapy-python3
import scapy.all as sp
import numpy as np
import sys
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

		host = {
			'ttl': packet.ttl,
			'failed': len(answers) == 0,
			'inaccurate': len(answers) < accuracy,
			'traceroute': {
				'time': packet_end - packet_start,
				'sent_packets': sent,
				'received_packets': recv,
				# TODO: convert these two into json or something like that
				'packet': packet,
				'answers': answers
			}
		}

		if not host['failed']:
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

			host.update({
				'failed': False,
				'selected': {
					'ip': selected_ip,
					'packets': selected,
				}
			})

		yield host

		if finished:
			break

def geolocate(host):
	def get_geolocation_data(ip):
		json = {}

		try:
			request = requests.get('http://ip-api.com/json/'+ip)
			json = request.json()
		except:
			json = {'status': 'fail'}

		if json['status'] != 'success':
			return None
		else:
			return json

	geoip = get_geolocation_data(host['selected']['ip'])

	if geoip is not None:
		host['selected']['geolocation'] = geoip

	return host

def estimate_rtt(host, accuracy = 20, packet_timeout=0.2, scan='icmp'):
	measures = []
	rtts = []

	packet = sp.IP(dst=host['selected']['ip'])

	if scan == 'icmp':
		packet = packet/sp.ICMP()
	elif scan == 'tcp':
		packet = packet/sp.TCP(dport=80, flags='S')
	elif scan == 'udp':
		packet = packet/sp.UDP()/sp.DNS(qd=sp.DNSQR(qname='whatever.com'))
	else:
		raise Exception('Unknown scan type')

	for iteration in range(accuracy):
		rtt = time.perf_counter()
		measure = sp.sr1(packet, timeout=packet_timeout, verbose=0)
		rtt = time.perf_counter() - rtt

		if measure is not None:
			measures.append((rtt, measure))
			rtts.append(rtt)

	if len(measures) > 0:
		host['selected']['ping'] = {
			'accuracy': accuracy,
			'measures': measures,
			'rtt_avg': np.average(rtts),
			'rtt_stdev': np.std(rtts)
		}
	elif scan=='icmp':
		host = estimate_rtt(host, accuracy, 2*packet_timeout, 'tcp')

	return host

def print_traceroute(trace):
	for host in trace:
		if host['failed']:
			print(host['ttl'], '*')
		else:
			host = geolocate(host)
			host = estimate_rtt(host)

			try:
				print(host['ttl'], host['selected']['ip'], host['selected']['ping']['rtt_avg'], host['selected']['geolocation']['countryCode'], host['selected']['geolocation']['regionName'])
				continue
			except:
				pass

			try:
				print(host['ttl'], host['selected']['ip'], host['selected']['ping']['rtt_avg'])
				continue
			except:
				pass

			try:
				print(host['ttl'], host['selected']['ip'], host['selected']['geolocation']['countryCode'], host['selected']['geolocation']['regionName'])
				continue
			except:
				pass

			print(host['ttl'], host['selected']['ip'])


# TODO: meter el objeto trace en mongodb, asi lo levantamos sabrosamente con tableau 

print_traceroute(traceroute(host, scan, accuracy, max_ttl, retries_per_attempt, packet_timeout))