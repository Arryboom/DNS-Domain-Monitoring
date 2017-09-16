#! /usr/bin/python
 
from scapy.all import *
import sys
import threading
import logging
 
def packet_handler(pkt):
	ip_src = ''
	ip_dest = ''
	protocol = ''
	domain_requested = ''

        if IP in pkt:
                ip_src = pkt[IP].src
                ip_dest = pkt[IP].dst   
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			domain_requested = str(pkt.getlayer(DNS).qd.qname)
	if TCP in pkt:
		protocol = 'TCP'
	else:
		protocol = 'UDP'

	asset_information = lookup_asset(ip_src)

	data = [ip_src, asset_information, ip_dest, protocol, domain_requested]
	logging.info('Data: ' + str(data) + '\n')

	if is_domain_analyzed(data) == True:
		logging.debug('Domain: ' + data[4] + ' has been analyzed\n')
	else:
		logging.debug('Domain: ' + data[4] + ' has NOT been analyzed\n')
		analyze_domain(data)

	domain_score = get_domain_score(data)

	risk_score = risk_calculation(data, domain_score)
		
		
def is_domain_analyzed(data):
	logging.debug('Checking DB for analysis information\n')
	return False

def analyze_domain(data):
	logging.debug('Running Domain analysis scripts\n')

def get_domain_score(data):
	logging.debug('Getting Domain score\n')
	return 10

def lookup_asset(ip_src):
	logging.debug('Looking up asset\n')
	return 'host'

def risk_calculation(data, score):
	logging.debug('Performing risk calculation\n')
	return score

def sniffer(interface, sniffer_filter):
	sniff(iface = interface,filter = sniffer_filter, prn = packet_handler, store = 0)

def main():
	if sys.argv[1]:
		interface = sys.argv[1]
		dns_server_ip = sys.argv[2]
	else:
		print 'Usage: ./dns_sniff.py [interface] [dns_server_ip]' 

	logging.debug('Sniffing on interface ' + interface + '\n')

	sniffer_filter = 'dst port 53 and ip dst not ' + dns_server_ip

	sniffer(interface, sniffer_filter)

if __name__ == '__main__':
	logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
	main()
	logging.info('Shutting Down\n')
