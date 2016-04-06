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

	while True:

		# hosts that responded to the pings
		pinged_hosts = sP_scan(ips)

		print pinged_hosts

		# find out what services has each host open
		for host in pinged_hosts:
			if host not in ips_info.keys():
				ips_info[host] = [{}, sV_scanner(host, ports)]
			else:
				ips_info[host].append(sV_scanner(host, ports))

		getDifferences()

		print ips_info


def getDifferences():
	global ips_info

	# in this section, we need find new hosts in the net  
	for host in ips_info:
		# last record
		actual_ports = ips_info[host][-1]
		
		# last -1
		last_ports = ips_info[host][-2]

		response = ""

		if actual_ports == {}:
			if last_ports == {}:
				response = ''
			else:
				response = host + ": wakes up with no ports open"
		elif actual_ports == last_ports:
			pass
		elif last_ports == {}:
			response = host + ": wakes up with ports " + ", ".join([str(port) + " (" + actual_ports[port]['name'] + ")" for port in actual_ports])
		else:
			response = host + ": modifies his opened ports: " + close_some_and_open_some_services(actual_ports, last_ports)

		print response





# here we find the differences between the open ports of the last record, and the record we just made
def close_some_and_open_some_services(actual, last):
	opened = []
	closed = [] 

	for i in actual:
		if i not in last:
			opened.append(i)

	for i in last:
		if i not in actual:
			closed.append(i)

	return "Opened ports: " + ", ".join(opened) + ". Closed ports: " + ", ".join(closed)



# This scanner finds up hosts in the ips range and returns the ones online in a string 
def sP_scan(ips):
	# first scanner to see who is online
	nm = nmap.PortScanner()

	# -sP option to use pings to determine who is hearing 
	nm.scan(hosts=ips, arguments='-sP')
	# nm.scan(hosts=ips)

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

	# when scanning a android, it returns a null array (dont know why)
	if nm == []:
		return {}

	try:
		# androids are tricky
		if 'tcp' in nm[host]:
			services = {}
			keys = nm[host]['tcp'].keys()
			for key in keys:
				# we only want the port and the service name, so thats what we return 
				services[key] = {'name': nm[host]['tcp'][key]['name']}
			return services
		else:
			return {}

	except KeyError:
		print "KeyError"
		return {}


# loads the global variables to be able to use them in the program
def load_globals():
	global ips_info
	ips_info = {}


if __name__ == "__main__":

	load_globals()

	ips = '192.168.100.10/24'
	ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)