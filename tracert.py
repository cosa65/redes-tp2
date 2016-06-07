#!/usr/bin/python3
# NOTES: run as root. To install dependencies: sudo pip3 install scapy-python3
import scapy.all as sp
import numpy as np
import sys
import time
import requests
from scipy import stats
from collections import defaultdict

# TODO: tomar parametros por consola para hacer esta chota
host = "google.com"
scan = "icmp" # ICMP, UDP or TCP
accuracy = 2 # Number of measures we want per TTL
retries_per_attempt = 2 # Maximum number of times to attempt to measure
packet_timeout = 0.2 # In fractional seconds
max_ttl = 50 # Maximum route length

if len(sys.argv) >= 2:
	host = sys.argv[1]
if len(sys.argv) >= 3:
	scan = sys.argv[2]
if len(sys.argv) >= 4:
	accuracy = int(sys.argv[3])
if len(sys.argv) >= 5:
	retries_per_attempt = int(sys.argv[4])
if len(sys.argv) >= 6:
	packet_timeout = float(sys.argv[5])
if len(sys.argv) >= 7:
	max_ttl = int(sys.argv[6])

def traceroute(dhost, scan='tcp', accuracy=20, max_ttl=50, retries_per_attempt=3, packet_timeout=0.2):
	packets = sp.IP(
		ttl=(1, max_ttl),
		dst=sp.Net(dhost))

	if scan == 'icmp':
		packets = packets/sp.ICMP(seq=0x1)
		iid = 9999
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
				if scan == 'icmp':
					packet.getlayer(sp.ICMP).id = iid
					iid += 1
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
			'dst': sp.Net(dhost),
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
			ips = defaultdict(list)

			for (rtt, answer) in answers:
				ips[answer.src].append((rtt, answer))

			# Select ip based on the number of answers, and whichever happened last

			selected_ip, selected = max(ips.items(), key=lambda a: len(a[1]))

			rtts = [answer[0] for answer in selected]

			host.update({
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

def estimate_rtt(host, accuracy = 20, packet_timeout=0.5, max_retries=40, scan='icmp'):
	measures = []
	rtts = []

	packet = sp.IP(dst=host['selected']['ip'])

	if scan == 'icmp':
		packet = packet/sp.ICMP(seq=0x1)
		iid = 9999
	elif scan == 'tcp':
		packet = packet/sp.TCP(dport=80, flags='S')
	elif scan == 'udp':
		packet = packet/sp.UDP()/sp.DNS(qd=sp.DNSQR(qname='whatever.com'))
	else:
		raise Exception('Unknown scan type')

	# for iteration in range(accuracy):
	# 	if scan == 'icmp':
	# 		packet.getlayer(sp.ICMP).id = iid
	# 		iid += 1
	# 	rtt = time.perf_counter()
	# 	measure = sp.sr1(packet, timeout=packet_timeout, verbose=0)
	# 	rtt = time.perf_counter() - rtt

	# 	if measure is not None:
	# 		measures.append((rtt, measure))
	# 		rtts.append(rtt)

	retries = 0
	packet.getlayer(sp.IP).dst = host['dst']
	packet.getlayer(sp.IP).ttl = host['ttl']
	while len(measures) < accuracy or retries >= max_retries:
		if scan == 'icmp':
			packet.getlayer(sp.ICMP).id = iid
			iid += 1
		rtt = time.perf_counter()
		measure = sp.sr1(packet, timeout=packet_timeout, verbose=0)
		rtt = time.perf_counter() - rtt

		if measure is not None:
			measures.append((rtt, measure))
			rtts.append(rtt)

	# print('--ertt: ip={}, measures={}'.format(host['selected']['ip'],len(measures)))

	if len(measures) > 0:
		host['selected']['ping'] = {
			'accuracy': accuracy,
			'measures': measures,
			'rtt_min' : min(rtts),
			'rtt_avg': np.average(rtts),
			'rtt_stdev': np.std(rtts)
		}

def cimbalaRec(trace):
	if len(trace) == 0:
		return
	mean = np.mean([host['selected']['ping']['rtt_cim'] for host in trace])
	std = np.std([host['selected']['ping']['rtt_cim'] for host in trace])

	for host in trace:
		host['selected']['ping']['absDev'] = abs(mean - host['selected']['ping']['rtt_cim'])

	#maxAbsDHostElement representa el router con mayor |mean - rtt_cim| de todos, va a ser el posible outlier en cada paso de la recursion
	maxAbsDHostIndex, maxAbsDHostElement = max(enumerate(trace), key=lambda item: item[1]['selected']['ping']['absDev'])
	delta = maxAbsDHostElement['selected']['ping']['absDev']
	n = len(trace)
	t = stats.t.ppf(1 - 0.025, n - 2)
	tau = (t * (n - 1)) / (np.sqrt(n) * np.sqrt(n - 2 + t**2))
	if delta > (std * tau):
		print("Enlace intercontinetal encontrado hacia: " + str(trace[maxAbsDHostIndex]['selected']['ip']))
		trace.pop(maxAbsDHostIndex)
		cimbalaRec(trace)

def cimbala(trace):
	#rtt_cim va a ser el rtt del salto de un router al siguiente, todos los calculos de cimbala se hacen en base a este valor
	for i in range(1, len(trace)):
		trace[i]['selected']['ping']['rtt_cim'] = trace[i]['selected']['ping']['rtt_avg'] - trace[i - 1]['selected']['ping']['rtt_avg']
		# print('IP={} Avg={} StdD={} Cim={}'.format(
		# 			trace[i]['selected']['ip'],
		# 			trace[i]['selected']['ping']['rtt_avg'],
		# 			trace[i]['selected']['ping']['rtt_stdev'],
		# 			trace[i]['selected']['ping']['rtt_cim']))
	cimbalaRec(trace[1:])

def print_traceroute(trace):
	total = []
	for host in trace:
		if host['failed']:
			print('{}	{}'.format(host['ttl'], '*'))
		else:
			geolocate(host)
			estimate_rtt(host, accuracy, packet_timeout, accuracy*2)

			output = [str(host['ttl']), host['selected']['ip']]
			if 'ping' in host['selected']:
				total.append(host)
				output.append('%.4f' % float(host['selected']['ping']['rtt_avg']))

			if 'geolocation' in host['selected']:
				if 'countryCode' in host['selected']['geolocation']:
					output.append(host['selected']['geolocation']['countryCode'])
				if 'regionName' in host['selected']['geolocation']:
					output.append(host['selected']['geolocation']['regionName'])
			print('	'.join(output))
	return total



# TODO: meter el objeto trace en mongodb, asi lo levantamos sabrosamente con tableau
cimbala(print_traceroute(traceroute(host, scan, accuracy, max_ttl, retries_per_attempt, packet_timeout)))
