#!/usr/bin/env python

import sys, time, os, platform, subprocess, socket, random
from optparse import OptionParser
from banners import bannerChoice
from banners import leaving
from datetime import datetime

######## INFO ######
autor = "Sh3llm4sk"
version = "0.2"
######## BANNERS ########

banner = bannerChoice()
ext = leaving()

######## FUNCTIONS ########


examples = """
	Example of usage:

		- Execute osiris and change the output file:

		> python ./osiris.py 192.168.1.1 -f

		- Execute osiris and scans from host 5 to host 100:

		> python ./osiris.py 192.168.1.5/100

		- Execute osiris with a domain name

		> python ./osiris.py www.facebook.com
	"""
def ping(addr):
#Performs a simple ICMP Request to check if the host is up.
	ops = platform.system()
	if (ops == "Windows"): #Dectects which OS is running.
		pingCmd = "-n 1"
	elif (ops == "Linux"):
		pingCmd = "-c"
	else :
		print "[!] We couldn't detect which OS are you running. Some scans may fail"
		pingCmd = "-c"
	try:
		FNULL = open(os.devnull, 'w') #/DEV/NULL
		icmpResponse = subprocess.call(['ping',pingCmd, "1", addr], stdout=FNULL, stderr=subprocess.STDOUT)#Preforms a ping and redirect output to /dev/null
		if icmpResponse == 0:
			return True
		else:
			return False
	except KeyboardInterrupt:
		print ext
		sys.exit()
def IPresolver(addr):
    # Resolve the IP address
	try:
		ipv4 = socket.gethostbyname(addr)
	except:
		print addr +": Unknown host"
	try:
		ipv4 = socket.gethostbyaddr(addr)
		print ipv4
	except:
		print ipv4
def portScan(port, addr):
	#Function used to scan the listed ports and see which ones are open
	try:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		con = s.connect_ex((addr,port))
		if (con == 0):
			return True
		else:
			return False
		s.close()
	except KeyboardInterrupt:
		print "[!] Stopping the scanner ..."
		print ext
		sys.exit()
	except socket.error:
		print "[!] Couldn't connect to the server"
def bannerGrab (addr, port):
	# Simple banner grab (This is going to be changed soon)
	try:
		s = socket.socket()
		s.connect((addr, port))
		msg = ""
		while len(msg) < 256:
			chunk = s.recv(100)
			introduction = "[+]=========[-]> "
			buf = introduction + chunk
			msg = msg + "\n" + buf
		return msg
	except:
		return "[+]=========[!]> Couldn't connect to the server\n[|]"


def randomIP(net):
	byte4 = random.randrange(1,254)
	scr_addr = net+byte4
	return scr_addr

######### VARIABLES ########

targets = [] 	# A list of targets to scan
targetsUp = [] 	# All the hosts up
# portsFile = open('ports.txt', 'r').readlines
ports = [21, 22, 23, 25, 49, 53, 80, 115, 137, 139, 156, 161, 194, 443, 546, 8080]
openPorts = [] 	# List of open ports
# outputFile = "/output/"+sys.argv[1]+".txt"
pingConfirm = False


### PARSER ###

usage = "usage: %prog -u <Target IP> [options]"
parser = OptionParser(usage=usage)
parser.add_option("-u", "--host", dest="Host", help="IP or domain of the target to scan")#, metavar="<IP>")
parser.add_option("-b", "--brute", action="store_true", dest="bruteForce", default=False, help="Use this option to enable brute force")
parser.add_option("-f", "--output", dest="outputFile", help="Specify the output path")
(options, args) = parser.parse_args()


if len(args) < 1:
	print "No enough arguments gievn"
	print examples
	sys.exit()
elif options.Host == " ":
	print "You must specify a target"
	sys.exit()
else:
	address = options.Host

############# ARGUMENTS IDENTIFICATION ############

if "/" in address: # If there's a slash on the IP this will check all the targets
	pingConfirm = False
	addS = address.split("/")
	ip = addS[0]
	hostRange = int(addS[1])
	netS = ip.split(".")
	net = netS[0]+"."+netS[1]+"."+netS[2]+"."
	firstIP = int(netS[3])
	for su in range(firstIP, hostRange):
		addr = net+str(su)
		targets.append(addr) #Stores the IPs in the targets lelif("-r"in sys.argv)or("--reverse"in sys.argv):
if(options.outputFile):
	#Output file
	pwd = subprocess.call(['pwd'])
	print "[?] Current output location: "+str(pwd)+"/output/"
	outputFileD = raw_input("[?] Do you want to specify a new output directory?(Y/N): ")
	if ((outputFileD=="y")or(outputFileD=="Y")):
		outputFile = raw_input("[>] Specify the path of the new output file: ")
		print "[!] New output file set to: " +outputFile
		targets.append(address)
	else:
		pass
		targets.append(address)
IPresolver(address)
targets.append(address)
ct = len(targets)
if ct != 0: # If there is no targets the program will finish
	print "[?] The number of: "+str(ct)+" hosts are going to be scanned."
else:
	print "[!] No targets found"
	print ext
	sys.exit()

######### ICMP Request #########

ti1 = datetime.now()
for t in targets:
	icmp = ping(t)
	if icmp == True: #If we have a ICMP Response the host will be up. The current target of the loop will be stored in targetsUp
		print "[!] The host "+t+" is up!"
		targetsUp.append(t)
	else:
		print "[>] The host "+t+" is down!"
		if pingConfirm == True: # If we are going to scan multiple hosts this option might be disabled
			quitPing = raw_input("[?] Do you want to (T)try again or (E)exit? (T/E): ")
			if ((quitPing == "T")or(quitPing=="t")):
				ping(t)
			elif ((quitPing=="E")or(quitPing=="e")):
				print ext
				sys.exit()
			else:
				print "[!!] Something went wrong... Exiting..."
				print ext
				sys.exit()
ti2 = datetime.now()
tit = ti2 -ti1
print "[?] The number of "+str(ct)+" hosts have been pinged in "+str(tit)
time.sleep(1)

############# PORT SCAN ##############

ts1 = datetime.now()
print "[>] Starting port scanner at: ", ts1
for i in targetsUp:
	print "[>] Scannig the target: " + i
	print "_"*60
	print ""
	for port in ports:
		ptrscn = portScan(port, i)
		if ptrscn == True:
			print "[|] "+str(i)+":"+str(port)+"/TCP	- OPEN"
			openPorts.append(port)
			print bannerGrab(i, port)
		else:
			print "[-] "+str(i)+":"+str(port)+"		- CLOSED\n[|]"
	print ""
	print "*"*60
	oPts = len(openPorts)
	if oPts == 0:
		print "[!] No open ports!"
	elif oPts > 0:
		print "[?] We have discovered "+str(oPts)+" open ports"
ts2 = datetime.now()
tst = ts2 - ts1
print "\n[?] The scanner took: ", tst, "to scan the ports"
#https://pentestlab.blog/2012/03/01/attacking-the-ftp-service/
