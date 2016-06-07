#!/usr/bin/python3
# NOTES: run as root. To install dependencies: sudo pip3 install scapy-python3
import numpy as np
import sys
import time
import requests
import logging
import random
from scipy import stats
from collections import defaultdict
from os import getuid


def traceroute(destination, scan, accuracy, max_ttl, retries_per_attempt, packet_timeout):
    destination = sp.Net(destination)

    packets = sp.IP(
        ttl=(1, max_ttl),
        dst=destination)

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
                if scan == 'icmp':
                    packet.getlayer(sp.ICMP).id = random.randint(0, 65535)

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

        packet_end = time.perf_counter()

        host = {
            'ttl': packet.ttl,
            'destination': packet.dst,
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
            request = requests.get('http://ip-api.com/json/{ip}'.format(ip=ip))
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


def ping(host, accuracy=20, packet_timeout=0.5, max_retries=40, scan='icmp'):
    measures = []
    rtts = []

    packet = sp.IP(dst=host['destination'], ttl=host['ttl'])

    if scan == 'icmp':
        packet = packet/sp.ICMP()
    elif scan == 'tcp':
        packet = packet/sp.TCP(dport=80, flags='S')
    elif scan == 'udp':
        packet = packet/sp.UDP()/sp.DNS(qd=sp.DNSQR(qname='whatever.com'))
    else:
        raise Exception('Unknown scan type')

    for attempt in range(accuracy):
        rtt = measure = None
        success = False

        for retry in range(max_retries):
            if scan == 'icmp':
                packet.getlayer(sp.ICMP).id = random.randint(0, 65535)

            rtt = time.perf_counter()
            measure = sp.sr1(packet, timeout=packet_timeout, verbose=0)
            rtt = time.perf_counter() - rtt

            if measure is not None:
                success = True
                break

        if success:
            measures.append((rtt, measure))
            rtts.append(rtt)

    if len(measures) > 0:
        host['selected']['ping'] = {
            'accuracy': accuracy,
            'measures': measures,
            'rtt_min' : min(rtts),
            'rtt_avg': np.average(rtts),
            'rtt_stdev': np.std(rtts)
        }


def augment(trace):
    for host in trace:
        if not host['failed']:
            geolocate(host)
            ping(host)

        yield host


def print_traceroute(trace):
    total = []

    for host in trace:
        if host['failed']:
            print('{}\t{}'.format(host['ttl'], '*'))
        else:
            output = [str(host['ttl']), host['selected']['ip'].ljust(15)]

            if 'ping' in host['selected']:
                total.append(host)
                output.append('%.4f' % float(host['selected']['ping']['rtt_avg']))

            if 'geolocation' in host['selected']:
                if 'countryCode' in host['selected']['geolocation']:
                    output.append(host['selected']['geolocation']['countryCode'])
                if 'regionName' in host['selected']['geolocation']:
                    output.append(host['selected']['geolocation']['regionName'])
            print('\t'.join(output))

    return total


def cimbala(trace):
    firstElement = True
    lastRtt = 0

    pending = []
    processed = []

    # Generamos los deltas
    for host in trace:
        if host['failed'] or 'ping' not in host['selected']:
            processed.append(host)
        else:
            # Nos salteamos el primer hop que haya andado bien
            if firstElement:
                firstElement = False
                processed.append(host)
            else:
                host['selected']['cimbala'] = {
                    'rtt': host['selected']['ping']['rtt_avg'] - lastRtt
                }

                print('IP={}, AVG={}, CIM={}'.format(
                    host['selected']['ip'],
                    host['selected']['ping']['rtt_avg'],
                    host['selected']['cimbala']['rtt']))

                pending.append(host)

            lastRtt = host['selected']['ping']['rtt_avg']

    # Vamos detectando outliers y sacandolos
    while len(pending) > 0:
        rtts = [host['selected']['cimbala']['rtt'] for host in pending]
        mean = np.mean(rtts)
        std = np.std(rtts)

        suspect_index = None
        suspect = None

        for (index, host) in enumerate(pending):
            host['selected']['cimbala']['deviation'] = abs(host['selected']['cimbala']['rtt'] - mean)

            if suspect is None:
                suspect_index = index
                suspect = host
            elif suspect['selected']['cimbala']['deviation'] <= host['selected']['cimbala']['deviation']:
                suspect_index = index
                suspect = host

        n = len(pending)
        t = stats.t.ppf(1 - 0.025, n - 2)
        tau = (t * (n - 1)) / (np.sqrt(n) * np.sqrt(n - 2 + t**2))

        if suspect['selected']['cimbala']['deviation'] > (std * tau):
            suspect['selected']['intercontinental'] = True
            print('INTERCONTINENTAL LINK DETECTED ', suspect['selected']['ip'], 'ttl:',suspect['ttl'])
            pending.pop(suspect_index)
            processed.append(suspect)
        else:
            break

    processed = processed + pending
    processed = sorted(processed, key=lambda host: host['ttl'])

    # Tecnicamente no tiene más sentido usar yield porque acá tenemos un cuello de botella, pero ya fue
    return processed

def dump(trace):
    pass


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sp

if getuid() != 0:
    print('This script needs to run as root')
    exit(1)

# TODO: tomar parametros por consola para hacer esta chota
host = "facebook.com"
traceroute_scan = "icmp" # ICMP, UDP or TCP
traceroute_accuracy = 2 # Number of measures we want per TTL
traceroute_retries_per_attempt = 2 # Maximum number of times to attempt to measure
traceroute_packet_timeout = 0.2 # In fractional seconds
traceroute_max_ttl = 30 # Maximum route length

if len(sys.argv) >= 2:
    host = sys.argv[1]
if len(sys.argv) >= 3:
    traceroute_scan = sys.argv[2]
if len(sys.argv) >= 4:
    traceroute_accuracy = int(sys.argv[3])
if len(sys.argv) >= 5:
    traceroute_retries_per_attempt = int(sys.argv[4])
if len(sys.argv) >= 6:
    traceroute_packet_timeout = float(sys.argv[5])
if len(sys.argv) >= 7:
    traceroute_max_ttl = int(sys.argv[6])

dump(
    cimbala(
        print_traceroute(
            augment(
                traceroute(
                    host,
                    traceroute_scan,
                    traceroute_accuracy,
                    traceroute_max_ttl,
                    traceroute_retries_per_attempt,
                    traceroute_packet_timeout
                    )
                )
            )
        )
    )