#! /usr/bin/python
from logging import getLogger, ERROR # Import Logging Things
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning
from optparse import OptionParser
try:
    from scapy.all import *
except:
    print "[!] Problem found importing scapy"
    print "[?] Try apt-get install scapy in order to install scapy before using Osiris"
import sys, os, platform, time, subprocess, random, socket
from datetime import datetime as dt# Other stuff
from time import strftime
from banners import bannerChoice
from banners import leaving
from brute import *
from progressbar import *

######## INFO ######
autor = "Sh3llmask"
version = "0.3"
######## BANNERS ########

banner = bannerChoice()
ext = leaving()

### VARS ###
target = ""
ports = range(1,100)
SYNACK = 0x12
RSTACK = 0x14
FNULL = open(os.devnull, 'w') #/DEV/NULL
password_path = 'sources/passwds.txt' #Path of the password dictionary
BRUTE_USER = "ftpuser"
interfaces = os.listdir('/sys/class/net/')
##### FLAGS #####

ICMP_PING = True
SYN_SCAN = True
BRUTE_FORCE = False
ANON_LOGIN = True
BANNER_GRAB = True

##### DICTS ##### (This will be changed)
services = {
	21:"FTP",
	22:"SSH",
	23:"TELNET",
	25:"SMTP",
	38:"RAP",
	39:"RLP",
	43:"WHOIS",
	50:"REMOTE MAIL CHECKING OR DRAT[Trojan]",
	53:"DNS",
	80:"HTTP",
	81:"TOR",
	82:"TOR",
	88:"KERBEROS AUTHENTICATION SYSTEM"
}
usage = """
	Example of usage:

		- Execute osiris and change the output file:

		> python ./osiris.py -u 192.168.1.1 -f /tmp/myfile.txt

		- Execute osiris and scans from host 5 to host 100:

		> python ./osiris.py -u 192.168.1.5/100

		- Execute osiris with a domain name

		> python ./osiris.py -u www.facebook.com
	"""

    ###############

def checking():
    # OS Detection
    ops = platform.system()
    if (ops != "Linux"):
        print "[!] Osiris is just for linux minds..."
        sys.close()

    if os.geteuid() != 0:
        print "[!] You must run Osiris as root user"
        sys.exit(1)

def IPresolver(addr):
    # Resolve the IP address
	try:
		return socket.gethostbyname(addr)
	except:
		print addr +": Unknown host"
	try:
		return socket.gethostbyaddr(addr)

	except:
		print ipv4

def ICMPing(addr):
    # Check if the host is up by a simple ICMP Ping
    conf.verb = 0
    TIMEOUT = 20
    global interfaces #Quick fix for interfaces
    try:
        pckt = IP(dst=addr, ttl=50)/ICMP() #Craft the ICMP packet
        reply = sr(pckt, iface=interfaces[1],verbose=0, timeout=TIMEOUT) # Sends the packet and stores the reply
        if reply != None:
            return True
        else:
            return False
    except Exception:
        print "[!] Something went wrong"
        return False
    except KeyboardInterrupt:
        print "[!] User interrupted the ICMP"
        print ext
        sys.exit(1)
def portScan(addr, port):
    try:
        conf.verb = 0
        srcPort = 6666
        SYN_ACK = IP(dst=addr)/TCP(sport=srcPort, dport=port, flags="S") #Craft a SYN-ACK Packet
        reply = sr1(SYN_ACK, timeout=10) #Send the packet to the destination port
        if reply is None: #If the reply is none the port is filtred
            return 2
        flags = reply.getlayer(TCP).flags #Extracting the flags of the reply
        if flags == SYNACK: #If the flags match then the port is open
            return 1
        else:
            return 0
        RST = send(IP(dst = addr)/TCP(sport=6666, dport=port, flags= "R")) # Returning a RST packet
    except KeyboardInterrupt:
        RST = send(IP(dst = addr)/TCP(sport=6666, dport=port, flags= "R"))
        print "[!] User requested to stop the scanner"
        print "[!] Leaving..."
        print ext
        sys.exit()
		
def bannerGrab(addr, port, serv):
	try:
		socket.setdefaulttimeout(1)
		conn = socket.socket()
		conn.connect((addr,port))
		buff = conn.recv(1024)
		msg = buff.split(" ")
		c = 0
		for g in msg:
			if ("." in g) and (g != addr):
				v = g.split(".")
			
			if serv in g:
				if len(g)>len(serv):
					return g
			c += c 
	except:
		return buff
### PARSER ###

usage = "usage: %prog -u <Target IP> [options]"
parser = OptionParser(usage=usage, version = "%prog "+version)
parser.add_option("-u", "--host", dest="Host", help="IP or domain of the target to scan", metavar="<IP>")
parser.add_option("-b", "--brute", action="store_true", dest="BRUTE_FORCE", default=False, help="Use this option to enable brute force")
parser.add_option("-f", "--output", dest="outputFile", help="Specify the output path")
(options, args) = parser.parse_args()
if len(sys.argv) < 2:
	print "No enough arguments given"
	print usage
	sys.exit()
elif options.Host is None:
	print "You must specify a target"
	sys.exit()
else:
	address = options.Host
checking()
######### VARIABLES ########

targets = [] 	# A list of targets to scan
targetsUp = [] 	# All the hosts up
ports = [21, 22, 23, 25, 49, 53, 80, 115, 137, 139, 156, 161, 194, 443, 546, 8080] #Ports to scan
openPorts = [] 	# List of open ports
BRUTE_FORCE = options.BRUTE_FORCE

if "/" in address: # If there's a slash on the IP this will check all the targets
	pingConfirm = False
	addS = address.split("/")
	ip = addS[0]
	hostRange = int(addS[1])+1
	netS = ip.split(".")
	net = netS[0]+"."+netS[1]+"."+netS[2]+"."
	firstIP = int(netS[3])
	for su in range(firstIP, hostRange):
		addr = net+str(su)
		targets.append(addr) #Stores the IPs in the targets list
else:
    address = IPresolver(address)
    targets.append(address)
ct = len(targets)
if ct != 0: # If there is no targets the program will finish
	print "[?] The number of: "+str(ct)+" hosts are going to be scanned."
else:
	print "[!] No targets found"
	print ext
	sys.exit()

######### ICMP Request #########

ti1 = dt.now()
for t in targets:
    if ICMPing(t):
        print "[!] The host "+t+" is up!"
        targetsUp.append(t)
    else:
        print "[>] The host "+t+" is down!"
ti2 = dt.now()
tit = ti2 -ti1
print "[?] The number of "+str(ct)+" hosts have been pinged in %s.%s seconds"%(tit.seconds, tit.microseconds)
time.sleep(1)

############# SYN SCAN ##############
if len(targetsUp) == 0:
    print "[!] No hosts to scan"
    sys.exit()
ts1 = dt.now()
print "[>] Starting port scanner at: ", ts1
for i in targetsUp:
    print "[>] Scannig the target: " + i
    print "_"*60
    print ""
    for port in ports:
		try:
			con = portScan(i, port)
		except KeyboardInterrupt:
			print ext
			sys.exit()
		if con == 1:
			openPorts.append(port)
			print "[+] "+str(i)+":"+str(port)+"	TCP			- OPEN"
			try:
				serv = services[port]
				print "[!] Service: "+bannerGrab(i, port, serv)
			except:
				print "[!] Service: Not found"
			print "[|]"
		elif con == 0:
			print "[-] "+str(i)+":"+str(port)+"	TCP			- CLOSED"
		elif con == 2:
			print "[-] "+str(i)+":"+str(port)+"	TCP			- FILTRED"
    print ""
    print "*"*60
    oPts = len(openPorts)
    if oPts == 0:
        print "[!] No open ports!"
    elif oPts > 0:
        print "[?] We have discovered "+str(oPts)+" open ports"
ts2 = dt.now()
tst = ts2 - ts1
print "\n[?] The scanner took: ", tst, "to scan the ports"


############# BRUTE FORCING ##############

#Anonymoys login attempt
con = 0
anon_passwd = ["anonymous", " ", "anonymous@", "ftp"]
for i in targetsUp:
	if 21 in openPorts:
		for pswd in anon_passwd:
			con = ftpbreaker(i, "anonymous", pswd)
			if con == 1:
				print "[!]{FTP-"+i+"} Anonymous login enabled"
		if con == 0:
			print "[-]{FTP-"+i+"} Anonymous login disabled"	
if BRUTE_FORCE:
	print "SELECT A SERVICE TO BRUTE: "
	print "[1]	- FTP\n[2]	- SSH\n[3]	- TELNET\n"
	ch = int(raw_input("[*] SELECT: "))
	while (ch < 1) or (ch > 3):
		print "[!] You must insert a number between 1 - 3"
		ch = raw_input("[*] SELECT: ")
	if ch == 1:
		BRUTE_PROTOCOL = "FTP"
	elif ch == 2:
		BRUTE_PROTOCOL = "SSH"
	elif ch == 3:
		BRUTE_PROTOCOL = "TELNET"
	else:
		print "[!] Something went wrong"
		sys.exit()
	print "[?] Setting the protocol to brute to: "+BRUTE_PROTOCOL 
	
	if len(targetsUp)>1:
		ch = raw_input("Do you want to bruteforce all the targets? (This may take a long time)(Y/n)")
		if (ch.upper == "Y") or (ch.upper == "YES"):
			#BRUTING ALL THE TARGETS
			print "[!] Not implemented yet."
			print "[?] Current version: "+version
		else:
			c = 1
			targetMenu = {}
			for t in targetsUp: # Creates a dictionary to store the targets and values
				targetMenu[c]=t
				print "["+str(c)+"]" +"	"+ t
				c += 1
			try:
				ch = raw_input("Select the target to brute (1/"+str(c-1)+"): ")
			except KeyboardInterrupt:
				print ext
				sys.exit()

			addr = targetMenu[int(ch)]
	else:
		addr = address
	
	widgets = ['[>] Brute: ', Percentage(), ' ', Bar(marker='#',left='[',right=']')]
	BRUTE_USER = "ftpuser"
	passwdLines = len(open(password_path).readlines())
	print "[>] Trying passwords for user: "+BRUTE_USER
	bar = ProgressBar(widgets=widgets, maxval=passwdLines)
	passwdsFile = open(password_path, 'r')
	bar.start()
	c=0
	t1 = dt.now()
	for passwd in passwdsFile:
		con = ftpbreaker(addr, BRUTE_USER, passwd)
		c+=1
		bar.update(c)
		if con == 1:
			break
	bar.finish()
	t2 = dt.now()
	t = t2-t1
	if con == 1:
		print "[!] Password found :) > "+passwd
	else:
		print "[!] No password found"
	print "[?] The brute force took: "+str(t)		
