
        [01001111 01110011 01101001 01110010 01101001 01110011] 
		
	Osiris is a python tool used to scan a host looking for open ports and its services.
	Actually osiris uses sockets to stablish a connection with the target host but this will be changed soon, 
	implementing a 3way handshake for more accuraccy scanner. Also 
	Osiris provides you a force brute tool for FTP, SSH and Telnet services. 
	This tool is quite new so many facts aren't fully implemented. 
	I want Osiris to be able to upload a reverse shell on the target if a vulnerabilitie is found. 
	For making easy to configure the tool I will add attack profiles where you can customice your own kind of scanner.

Usage: 

	python ./osiris.py -u <target> [options]
	
	-u or --host <target>	IP or domain of the target to scan
	-b or --brute		Enables the brute force 
	-f or --output <path>	Specify the output file // Not working yet
	-h or --help		Show info about osiris
	-c or --config		Change the default parameters (Not working yet)
	--version		Prints the version of osiris
	
	
	Example of usage:
		- Run a SYN scan and try to brute force:
		> sudo python ./osiris.py -u <target> -b
		
		- Execute osiris and change the output file:
		
		> python sudo ./osiris.py -u 192.168.1.1 -f /tmp/192.168.1.1-scan.txt
	
		- Execute osiris and scans from host 5 to host 100:
		
		> python sudo ./osiris.py -u 192.168.1.5/100 (You may have some problems on version 0.3 with this)
		
		- Execute osiris with a domain name 
		
		> python sudo ./osiris.py -u http://www.facebook.com/ 
		
Requeriments:
	
	Osiris is designed for Linux minds. 
	You'll need to have python2.7 installed to run this tool
	Since version 0.3 you need Scapy to run this tool (apt intall scapy)
	You must run this tool as sudo

Autor:

	@Sh3llmask 
	Special thanks to @someone25 :)
	
[!] Happy Hunting boyz [!]
	
