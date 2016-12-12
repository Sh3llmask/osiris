
        [01001111 01110011 01101001 01110010 01101001 01110011] 
		
	Osiris is a python tool used to scan a host looking for open ports and its services. Actually osiris uses sockets to stablish a 	connection with the target host but this will be changed soon, implementing a 3way handshake for more accuraccy scanner. Also 
	Osiris provides you a force brute tool for FTP, SSH and Telnet services. This tool is quite new so many facts aren't fully 		implemented. I want Osiris to be able to upload a reverse shell on the target if a vulnerabilitie is found. For making easy to 		configure the tool I will add attack profiles where you can customice your own kind of scanner.
	
	Osiris is a python tool used to scan a network looking for available hosts, and which ports have each host open. It simply 
	uses ECHO Requests to test if the host is up. Also Osiris uses sockets to check which ports are open.
	Furthermore Osiris provides you a description for each port and the services that can be running on it.

Usage: 

	python ./osiris.py -u <target> [options]
	
	-u or --host <target>	IP or domain of the target to scan
	-b or --brute		Enables the brute force // Not working yet
	-f or --output <path>	Specify the output file // Not working yet
	-r or --reverse		Converts the hostname to IPv4 format (This is going to be changed)
	-h or --help		Show info about osiris
	--version		Prints the version of osiris
	
	
	Example of usage:
		
		- Execute osiris and change the output file:
		
		> python ./osiris.py -u 192.168.1.1 -f /tmp/192.168.1.1-scan.txt
	
		- Execute osiris and scans from host 5 to host 100:
		
		> python ./osiris.py -u 192.168.1.5/100 (You may have some problems on version 0.2 with this)
		
		- Execute osiris with a domain name 
		
		> python ./osiris.py -u http://www.facebook.com/ -r
		
Requeriments:
	
	Osiris only working on Windows and Linux
	You'll need to have python2.7 installed to run this tool

Autor:
	
	You can contact with me through email: meisterlinux@protonmail.com
	You can follow me on twitter as @linuxm3ister
	
[!] Happy Hunting boyz [!]
	
