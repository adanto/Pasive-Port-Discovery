#!/usr/bin/env python

import sys
import nmap

# import time

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

	# find out what services has each host open
	for host in pinged_hosts:
		if host not in ips_info.keys():
			ips_info[host] = [{}, sV_scanner(host, ports)]
		else:
			ips_info[host].append(sV_scanner(host, ports))

	getDifferences()


def getDifferences():
	global ips_info

	# in this section, we need find new hosts in the net  
	for host in ips_info:
		# last record
		actual_ports = ips_info[host][-1]
		
		# last -1
		last_ports = ips_info[host][-2]

		differences = []
		for key in actual_ports:
			if key in last_ports or last_ports == {}:
				# this user was online in the last record
				if last_ports[key] == actual_ports[key]:
					# still the same
					pass
				else:
					differences.append(key + ": " + close_some_and_open_some_services(actual_ports[key], last_ports[key]))
			else:
				# this user was not online in the last record
				differences.append(key + ": wakes up with ports " + ", ".join(actual_ports))


# here we find the differences between the open ports of the last record, and the record we just made
def close_some_and_open_some_services(actual, last):
	opened = []
	closed = [] 

	for i in actual:
		if i in last:
			pass
		else:
			opened.append(i)

	for i in last:
		if i in actual:
			pass
		else:
			closed.append(i)

	return "Opened ports: " + ", ".join(opened) + ". Closed ports: " + ", ".join(closed)



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

	if 'tcp' in nm[host]:
		services = {}
		keys = nm[host]['tcp'].keys()
		for key in keys:
			# we only want the port and the service name, so thats what we return 
			services[key] = {'name': nm[host]['tcp'][key]['name']}
		return services
	else:
		return {}


# loads the global variables to be able to use them in the program
def load_globals():
	global ips_info
	ips_info = {}


if __name__ == "__main__":

	load_globals()

	ips = '192.168.100.1'
	ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)