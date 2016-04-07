#!/usr/bin/env python

import sys
# necessary to get arguments
import getopt

import nmap
import json

import requests

import time

################################################################################
###############################     HELP     ###################################
################################################################################

def usage():
	print "\nPasive Port Discovery"
	print
	print " Usage: ./scanner.py -t <Token> -c <conversation id> -o <output.file> -i <target ip> -p <ports>" 
	print "   -h --help 		- opens this help"
	print "   -t --token 		- token from the bot that you want to use"
	print "   -c --chat_id 	- chats id where you want to send the messages"
	print "   -o --output 		- output file where you want to store the JSON record"
	print "   -i --ips 		- ips that you want to scan. See the examples to understand the types"
	print "   -p --ports 		- ports that you want to scan. See the examples below"
	print 
	print 
	print " Examples:"
	print "   python scanner.py -t bot123:32112332112312123123 -c 1235 -o output.json -i 192.168.100.0 -p 80"
	print "   python scanner.py -t bot123:32112332112312123123 -c 1235 -o output.json -i 192.168.100.0 -p 80-1000"
	print "   python scanner.py -t bot123:32112332112312123123 -c 1235 -o output.json -i 192.168.100.0/24 -p 80"
	print "   python scanner.py -t bot123:32112332112312123123 -c 1235 -o output.json -i 192.168.100.1,192.168.100.2 -p 80"
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

	repetition = 0

	while True:

		# it always enters the first time
		if repetition % 2 == 0:

			print "[*] Scanning for up hosts"

			# hosts that responded to the pings
			pinged_hosts = sP_scan(ips)

		# no need to print this lol
		# print pinged_hosts

		print "[*] Scanning services for", len(pinged_hosts), "up hosts"
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

		# no differences
		if len(comments) == 0:
			print "[*] There was no new info, waiting time increased"
			repetition = (repetition + 1) % 2
		else:
			print "[*] New info, reloading waiting time"
			repetition = 0

		# we are gonna wait 1 minute + 3 * repetition
		print "[*] Waiting for", 300 + 120 * repetition, 'seconds'
		time.sleep(300 + 60 * repetition)



def writeDictInfoToFile():
	with open(OUTPUT_FILE, 'w') as f:
		f.write(json.dumps(IPS_INFO, separators=(',',':')))


def sendMessagesToBot(comments):

	myBot = bot(TOKEN, CHAT_ID)

	if len(comments) > 0:

		myBot.sendPostMessage('######################\n## Updates from ' + str(time.strftime("%H:%M:%S") + ' ##\n######################'))
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
			closed += str(i) + " (" + last[i]['name'] + "), "

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
		print '[*] There was an error with the parameters'
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
				if nm[host]['tcp'][key]['state'] == 'open':
					# we only want the port and the service name, so thats what we return 
					services[key] = {'name': nm[host]['tcp'][key]['name']}
			return services
		else:
			return {'status':'online', 'timestamp': getCurrentTimestamp()}

	except KeyError:
		return {'status':'online', 'timestamp': getCurrentTimestamp()}


# this method returns the current time difference since the start of the app
def getCurrentTimestamp():
	return time.time() - INITIAL_TIME

# loads the global variables to be able to use them in the program
def load_globals():
	print "[*] Loading global variables"  
	global IPS_INFO
	global INITIAL_TIME
	global TOKEN
	global CHAT_ID
	global OUTPUT_FILE


	TOKEN = ""
	CHAT_ID = ""
	OUTPUT_FILE = ""
	ips = ""
	ports = ""
	
	try:
		opts, args = getopt.getopt(sys.argv[1:],"ht:c:o:i:p:",["target", "chat_id", "output", "ips", "ports"])
	except getopt.GetoptError:
		usage()

	for opt, arg in opts:
		if opt == '-h':
			usage()
		elif opt in ("-t", "--token"):
			TOKEN = arg
		elif opt in ("-c", "--chat_id"):
			CHAT_ID = arg
		elif opt in ("-o", "--output"):
			OUTPUT_FILE = arg
		elif opt in ("-i", "--ips"):
			ips = arg
		elif opt in ("-p", "--ports"):
			ports = arg


	if TOKEN == "" or CHAT_ID == "" or OUTPUT_FILE == "" or ips == "" or ports == "":
		usage()


	INITIAL_TIME = time.time()
	IPS_INFO = {}



	return ips, ports


if __name__ == "__main__":

	print "[*] Starting scanner.py"  

	ips, ports = load_globals()

	# ips = '192.168.100.11/24'
	# ports = '1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080'

	main_manager(ips, ports)