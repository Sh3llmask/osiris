
#############################################################################
    ## ##### ##  ## ####### ######### ########    ########     ## #########
   ##	    ##  ##            ##      ##      ##     ##       ##
   ##       ## ##            ##       ##     ##      ##      ##
  ##       ## ######## ##    ##       ## ## ##       ##      ######### ##
 ##       ##	      ##    ##        ##  ##         ##               ## 
 ##       ##	     ##     ##        ##   ##        ##              ## 
## ##### ## ########## ###########    ##    ##   ########## ##########
#############################################################################
        [01001111 01110011 01101001 01110010 01101001 01110011] 
		

	Osiris is a python tool used to scan a network looking for available hosts, and which ports have each host open. It simply 
	uses ECHO Requests to test if the host is up. Also Osiris uses sockets to check which ports are open.
	Furthermore Osiris provides you a description for each port and the services that can be running on it.

Usage: 

	python ./osiris.py <target> [Parameters]
	
	-S [--stealth : Preform a stealth scan]
	-a [--auto : Standard parameter to scan and find vulnerabilities]
	-f [ -f (path) : Specify a path for the output file. The default directory is: /output/]
	-r [--reverse : Take a hostname as a target]
	-b [Scan the network to find devices]
	
	Example of usage:
		
		- Execute osiris and change the output file:
		
		> python ./osiris.py 192.168.1.1 -f 
	
		- Execute osiris and scans from host 5 to host 100:
		
		> python ./osiris.py 192.168.1.5/100 
		
		- Execute osiris with a domain name 
		
		> python ./osiris.py http://www.facebook.com/ -r
		
Requeriments:
	
	Osiris only working on Windows and Linux
	You'll need to have python installed to run this tool

Autor:
	
	You can contact with me through email: m3isterlinux@protonmail.com
	You can follow me on twitter as @linuxm3ister
	
[!] Happy Hunting boyz [!]
	