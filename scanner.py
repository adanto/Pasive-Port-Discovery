#!/usr/bin/env python

import sys
import nmap
import json

import requests

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
	def __init__(self, token, chat_id):
		self.token = token
		self.chat_id = chat_id

	def sendPostMessage(self, text):
		r = requests.post('https://api.telegram.org/' + self.token + '/sendMessage', data = {'text': text, 'chat_id': self.chat_id})
		return r

	def getUpdates(self):
		r = requests.get('https://api.telegram.org/' + self.token + '/getUpdates')
		return r.text
		


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

		writeDictInfoToFile()

		# comments to send to telegram
		comments = getDifferencesInText()

		sendMessagesToBot(comments)

		print "waiting..."

		time.sleep(3)


def writeDictInfoToFile():
	with open('output', 'w') as f:
		f.write(json.dumps(IPS_INFO, separators=(',',':')))


def sendMessagesToBot(comments):

	myBot = bot('bot217362196:AAHZNgkySqsbbIfPTWzCE1NYquVcCZovHno', 8778776)

	if len(comments) > 0:
		myBot.sendPostMessage('##### Updates from ' + str(time.strftime("%H:%M:%S") + ' #####'))
		for com in comments:
			myBot.sendPostMessage(com)


# returns the news about all the hosts in an array
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

		if actual_ports['status'] == 'offline':
			if last_ports['status'] == 'offline':
				pass
			else:
				# it was online, not anymore... rip 
				comment = host + ": shuts down"

		elif actual_ports.keys() == ['status', 'timestamp'] and last_ports['status'] == 'offline':
			# wow! we found a mobile! and it has no open ports! D: 
			comment = host + ": wakes up with no ports apparently open"

		elif actual_ports.keys() == last_ports.keys():
			# same ports
			pass

		elif last_ports['status'] == 'offline':
			# we were offline, but now we have started listening

			comment = host + ": wakes up with ports " + ", ".join([str(port) + " (" + actual_ports[port]['name'] + ")" for port in actual_ports if port != 'status' and port != 'timestamp'])

		else:
			comment = host + ": modifies his opened ports: " + close_some_and_open_some_services(actual_ports, last_ports)

		if comment:
			responses.append(comment)


	return responses


# here we find the differences between the open ports of the last record, and the record we just made
def close_some_and_open_some_services(actual, last):
	opened = ""
	closed = ""

	i = 0

	# we need some error handling because there are times when we think that there is an open port, but when we try to test it, it's not open anymore
	try:
		# sometimes, we open(?) the ports in the middle of a scan
		for i in actual:
			if i != 'status' and i != 'timestamp':
				if i not in last:
					opened += str(i) + " (" + actual[i]['name'] + "), "
	except KeyError:
		opened += str(i) + " (" + actual[i]['name'] + "), "

	finally:

		try:
			# sometimes, we close the ports in the middle of a scan
			for i in last:
				if i != 'status' and i != 'timestamp':
					if i not in actual:
						closed += str(i) + " (" + last[i]['name'] + "), "
			
		except KeyError:
			print "here!!"
			closed += str(i) + " (" + last[i]['name'] + "), "
			print "closed here -> " + closed

		finally:

			if opened:
				opened = opened[:-2]
			else:
				opened = "None"

			
			if closed:
				closed = closed[:-2]
			else:
				closed = "None"

			# at the end, we get what we want BANZAII
			return "Opened ports: " + opened + ". Closed ports: " + closed

	


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

	ips = '192.168.100.11'
	ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)