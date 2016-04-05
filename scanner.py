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
	# hosts that responded to the pings
	pinged_hosts = sP_scan(ips)

	for host in pinged_hosts:
		print host
		print sV_scanner(host, ports)



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

	return nm[host]['tcp'].keys()
	
	
def sV_scanner_Callback(host, info):
	global ips_info

	print host, info

	ips_info[host] = info


# loads the global variables to be able to use them un the program
def load_globals():
	global ips_info
	ips_info = {}

if __name__ == "__main__":

	load_globals()

	ips = '127.0.0.1'
	ports = '1-1000'

	main_manager(ips, ports)