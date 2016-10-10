#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
###########################################
######### INFORMATION #####################
######### GATHERING   ###### v0.1 #########
###########################################
# Autor: @Sh3llm4sk                       #
###########################################
autor = "sh3llm4sk"
version = "0.1"

import sys
import time
import os
import platform
import subprocess
from argparse import ArgumentParser
import socket
from banners import bannerChoice
from banners import leaving
from datetime import datetime
banner = bannerChoice()
help = """
	Usage description: 
	-S [--stealth : Preform a stealth scan]
	-a [--auto : Standard parameter to scan and find vulnerabilities]
	-f [ -f (path) : Specify a path for the output file]
	-R [--reverse : Take a hostname as a target]
	
	Example of usage:
	python ./osiris.py <target> [Parameters]
"""
ports = [21,22,25,53,80,139,443,445,1080,3128,8080,8081]
openPorts = []
closedPorts = []
# #Argument set
# argparse = argparse.ArgumentParser()
# #	version ='0.1',
# #	description='OSIRIS us a automatic network scan which uses nmap and other tools to preform a deep scan of a target IP'
# #)
# parser.add_argument('-a', '--auto', help="Preforms a standar scan on the IP target")
# parser.add_argument('-s', '--stealth', help='Set the scan mode to stealth')
# parser.add_argument('-f', '--file', type=str, help='Specify the path of the output txt file')
# parser.add_argument('-o', '--objective', help='Specify the IP address of the target')
# args = parser.parse_args()
#The checker function is used to confirm if all the needed packages are installed
ext = leaving()
def checker():
	#Checker function is used to check all the needed things to run this tool
	FNULL = open(os.devnull, 'w')
	try:
		#First checks if the nmap is installed
		nmap = subprocess.call(['nmap','-V'], stdout=FNULL, stderr=subprocess.STDOUT)
		nmapInstalled = True
		print "[>] Nmap already installed"
	except:
		print "[>] Installing nmap..."
		nmapInst = raw_input("[?] Do you want to proceed?(Y/N): ")
		if ((nmapInst == "Y") or (nmapInst =="y")):
			print "[?] Installing..."
			nmapInstalled = True
		elif ((nmapInst == "N")or(nmapInst == "n")):
			print "[!] - You need nmap to run this tool -\nLeaving... "
			print ext
			sys.exit()
			
		else:
			print "[!] Wrong option... Leaving!"
			sys.close
	if (nmapInstalled == True): #Check all the checkers...
		checked = True
		time.sleep(1)
	else:
		print "[!] Something went wrong with the checker\n[!] Please re-run the tool again"
		time.sleep(1)
		print ext
		sys.exit()
	time.sleep(1)

def start(argv):
#This is the main function. Starts the tool and analizes the arguments given..
	if len(sys.argv) < 2:
		print banner
		print help
		print ext
		sys.exit()
	elif "-b" in sys.argv:
		print "-b option selected"
	else:
		print banner
		checker()
			
def icmpRequest(IP):
#Performs an ICMP Request to check if the host is up
	#Identify the operating system running
	ops = platform.system()
	if (ops == "Windows"):
		pingCmd = "n 1"
		# print "[!] Only for Linux minds."
		# print ext
		# sys.exit()
	elif (ops == "Linux"):
		pingCmd = "-c 1 "
	else :
		pingCmd = "-c 1 "
	for i in IP:
		print "[>] Checking if the host " + i + " is up! " 
		try:
			FNULL = open(os.devnull, 'w')
			icmpResponse = subprocess.call(['ping',  i], stdout=FNULL, stderr=subprocess.STDOUT)
			if icmpResponse == 0:
				print "[!] The host is up!"
				time.sleep(1)			
			else:
				print "[>] The host is down!"
				quitPing = raw_input("[?] Do you want to (T)try again or (E)exit? (T/E): ")
				time.sleep(1)
				if ((quitPing == "T")or(quitPing=="t")):
					icmpRequest(IP)
				elif ((quitPing=="E")or(quitPing=="e")):
					print ext
					sys.exit()
				else:
					print "[!!] Something went wrong... Exiting..."
					print ext
					sys.exit()
		except KeyboardInterrupt:
			print ext
			sys.exit()
#def networkScan():
	#Search the network for avaliable hosts
def portChecker(ports, IP):
	#This function creates a socket and scans each port of the "ports" list
	#Finally prints the status of each port
	t1 = datetime.now()
	print "[>] Starting port scanner at: ", t1
	try:
		for i in IP:
			print "[>] Scannig the target: " + i 
			print "_"*60
			print ""
			for port in ports:
				s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				socket.setdefaulttimeout(1)
				portscan = s.connect_ex((i,port))
				if (portscan == 0):
					print "[|] "+str(i)+":"+str(port)+"	- OPEN"
					openPorts.append(port)
				else:
					print "[-] "+str(i)+":"+str(port)+"	- CLOSED"
				s.close()
	except KeyboardInterrupt:
		print "[?] Stopping the scanner ..."
		print ext
		sys.exit()
	except socket.error:
		print "[!] Couldn't connect to the server"
	t2 = datetime.now()
	tt = t2 - t1
	print "\n[?] The scanner took: ", tt, "to scan the ports"
	
# if (sys.argv == "-r") or (sys.argv == "--reverse"):
			# If the host is provided by a domain address 
			# Converts the hostname to IPv4 format
			# ipv4 = socket.gethostbyname('sys.argv[1]')
			# targetIP = ipv4				
start(sys.argv)
IP = [sys.argv[1]]
outputFile = "/output/"+sys.argv[1]+".txt"
icmpRequest(IP)
portChecker(ports, IP)
