#!/usr/bin/env python

import sys
import nmap

import urllib2

import time

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


global IPS_INFO
global INITIAL_TIME


class bot:
	def __init__(self, url):
		self.url = url

	def sendMessage(self, chat_id, text):
		urllib2.urlopen(self.url + '/sendMessage?chat_id=' + str(chat_id) + '&text=' + text)


def main_manager(ips, ports):
	global IPS_INFO

	while True:

		# hosts that responded to the pings
		pinged_hosts = sP_scan(ips)

		print pinged_hosts

		# find out what services has each host open
		for host in pinged_hosts:
			if host not in IPS_INFO.keys():
				IPS_INFO[host] = [{'status':'offline', 'timestamp': getCurrentTimestamp()}, sV_scanner(host, ports)]
			else:
				IPS_INFO[host].append(sV_scanner(host, ports))

		# we need to update the hosts in the list that now are offline with no services
		for host in IPS_INFO:
			if host not in pinged_hosts:
				IPS_INFO[host].append({'status':'offline', 'timestamp': getCurrentTimestamp()})

		print IPS_INFO

		# comments to send to telegram
		# comments = getDifferencesInText()



##########################################################################
###########################     TESTING     ##############################
##########################################################################



def getDifferencesInText():
	global IPS_INFO

	responses = []

	# in this section, we need find new hosts in the net  
	for host in IPS_INFO:
		# last record
		actual_ports = IPS_INFO[host][-1]
		
		# last -1
		last_ports = IPS_INFO[host][-2]

		comment = ""

		if actual_ports == {}:
			if last_ports == {}:
				comment = ''
			else:
				comment = host + ": wakes up with no ports open"
		elif actual_ports == last_ports:
			pass
		elif last_ports == {}:
			comment = host + ": wakes up with ports " + ", ".join([str(port) + " (" + actual_ports[port]['name'] + ")" for port in actual_ports])
		else:
			comment = host + ": modifies his opened ports: " + close_some_and_open_some_services(actual_ports, last_ports)

		if comment:
			responses.append(comment)

	return responses


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




##########################################################################
###########################     TESTING     ##############################
##########################################################################





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
		return {'status':'online', 'timestamp': getCurrentTimestamp()}

	try:
		# androids are tricky
		if 'tcp' in nm[host]:
			services = {'status':'online', 'timestamp': getCurrentTimestamp()}
			keys = nm[host]['tcp'].keys()
			for key in keys:
				# we only want the port and the service name, so thats what we return 
				services[key] = {'name': nm[host]['tcp'][key]['name']}
			return services
		else:
			return {'status':'online', 'timestamp': getCurrentTimestamp()}

	except KeyError:
		print "KeyError"
		return {'status':'online', 'timestamp': getCurrentTimestamp()}


# this method returns the current time difference since the start of the app
def getCurrentTimestamp():
	return time.time() - INITIAL_TIME

# loads the global variables to be able to use them in the program
def load_globals():
	global IPS_INFO
	global INITIAL_TIME
	INITIAL_TIME = time.time()
	IPS_INFO = {}


if __name__ == "__main__":

	load_globals()

	ips = '192.168.100.0/24'
	ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)