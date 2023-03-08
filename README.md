# b4blood  
![banner](https://user-images.githubusercontent.com/123097488/222904224-0211b704-f5ad-47b0-87ed-df5a838fa168.png)  


Just a wrapper, scans for a breach in Active Directory to gain access to your first shell.  

* Scans the DC, time sync for Kerberos  
* Scans for SMB vulns
* Kerbrutes users/passwords, you can provide your own users list (-U my_userslist.txt) and/or your password list (-P passlist.txt) 
* Checks for AS-REP roasting and launch rockyou.txt against the hash  
* Dumps AD
* Scans recursively SMB/NFS shares and dumps juicy files (could be long, --nsd to skip this part)
* Scans for .xml GPP files in SYSVOL and extracts passwords  
* Scans for remote connections  
* Scans for Kerberoastable accounts  
* Dumps NTDS.DIT  


Very useful for CTF's, this is a nice tool before BloodHound ingestor.  
Could be use for internal audit with these options: --internal -i eth0  


# Installation (KALI)  
```sh
git clone https://github.com/moloch54/b4blood  
sudo python3 b4blood/setup.py  
```

Download kerbrute for your computer (amd64 or 386 CPU):  
https://github.com/ropnop/kerbrute/releases  
Rename it to "kerbrute"  

```sh
cd ~/Downloads
sudo cp kerbrute /usr/bin
sudo chmod +x /usr/bin/kerbrute  
```


| :warning: WARNING                                     |
|:------------------------------------------------------|
|rockyou.txt must be in /usr/share/wordlists/rockyou.txt|  
|xato-net-10-million-usernames must be in /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt| 


| :warning: WARNING2                                                                                                      |
| :-----------------------------------------------------------------------------------------------------------------------|
|If Impacket is already installed, you need to specifie line 12 in /usr/bin/b4blood YOUR own path for impacket/examples:  |   
path_impacket="/opt/impacket/examples"                                                                                    |  

# Usage  

```sh
USAGE:  
First make a folder, a lot of logs will be written.  

mkdir myfolder; cd myfolder  

b4blood --ip 192.168.0.45  
b4blood --ip 192.168.0.0/24  
b4blood --ip 192.168.0.* -U users.txt -P passwd.txt  

b4blood --internal -i eth0  
```  
  
# Features

* Scans the DC, time sync for Kerberos  
![synchro](https://user-images.githubusercontent.com/123097488/222896000-3bdea77c-2f4d-4e5b-b2ca-24814e7c912d.png)  

* Scans for SMB vulns  
![smb_vuln](https://user-images.githubusercontent.com/123097488/222903594-b49be048-d172-4dee-ac3d-3df82845d326.png)  

* Kerbrutes users/passwords, you can provide your own users list (-U my_userslist.txt) and/or your password list (-P passlist.txt) 
![ker](https://user-images.githubusercontent.com/123097488/222896214-a5e4d54c-d1e8-4732-bdcd-92c4b12c2c28.png)  

* Checks for AS-REP roasting and launches rockyou.txt against the hash  
![asrep](https://user-images.githubusercontent.com/123097488/222895707-124849b4-3303-4d23-b23e-e2c658e524ac.png)  

* Dumps AD
![ldap](https://user-images.githubusercontent.com/123097488/222896889-b57679de-210e-46ff-b2e4-e15baaead00b.png)  

* Scans recursively SMB/NFS shares and dumps juicy files (could be long, --nsd to skip this part)
![smb_shares](https://user-images.githubusercontent.com/123097488/222895755-c1b764dc-52a8-4a49-9fdb-22ff1b862764.png)  
![smb_dump](https://user-images.githubusercontent.com/123097488/222895744-8e1cc8cd-663d-48f3-96d0-9b1b9deeb347.png)  
![NFS](https://user-images.githubusercontent.com/123097488/222901480-ab46b68e-353b-4121-a451-9d4fbb8ad9c8.png)  


* Scans for .xml GPP files in SYSVOL and extracts passwords  
![gpp](https://user-images.githubusercontent.com/123097488/222903003-0bd05c02-6c6a-47d5-8837-82eff2ced89c.png)  

* Scans for remote connections  
![ssh](https://user-images.githubusercontent.com/123097488/222895583-44424f0f-0f6e-4fce-a077-e8f38ceb8f46.png) 

* Scans for Kerberoastable accounts  
![kerberostable](https://user-images.githubusercontent.com/123097488/222897588-f6be19af-f187-43af-b0a7-c1706a949ad1.png)  

Add your new creds to all_creds.txt and relaunch b4blood  

* Dumps NTDS.DIT  
![ntds](https://user-images.githubusercontent.com/123097488/222900861-45b1fb57-787a-4283-920f-41a66aa3b1d0.png)  














