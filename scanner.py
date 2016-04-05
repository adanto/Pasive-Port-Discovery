#!/usr/bin/env python

import sys
import nmap

################################################################################
###############################     HELP     ###################################
################################################################################

def usage():
	print "Pasive Port Discovery"
	print
	print "Usage: ./scanner.py -a <API key> -c <conversation id>"
	print 
	print

	sys.exit(0)

################################################################################
###############################  END OF HELP  ##################################
################################################################################


global ips_info


def main_manager(ips, ports):
	global ips_info

	# hosts that responded to the pings
	pinged_hosts = sP_scan(ips)

	for host in pinged_hosts:
		if host not in ips_info.keys():
			ips_info[host] = [{}, sV_scanner(host, ports)]
		else:
			ips_info[host][0] = ips_info[host][0]
			ips_info[host][1] = sV_scanner(host, ports)

	print ips_info




# This scanner finds up hosts in a ips range and returns the ones online in a string 
def sP_scan(ips):
	# first scanner to see who is online
	nm = nmap.PortScanner()

	# -sP option to use pings to determine who is hearing 
	nm.scan(hosts=ips, arguments='-sP')

	return nm.all_hosts()


# This scanner only finds the open services of a given host
def sV_scanner(host, ports):
	# only one ip please
	if len(host.split()) > 1:
		usage()

	# we create the port scanner
	nm = nmap.PortScanner()

	# initialize the scanner
	nm.scan(host, ports)

	# testing if there were any errors
	if 'error' in nm.scaninfo():
		print 'There was an error with the parameters'
		usage()

	return nm[host]


# loads the global variables to be able to use them in the program
def load_globals():
	global ips_info
	ips_info = {}

if __name__ == "__main__":

	load_globals()

	ips = '192.168.100.11/24'
	ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)