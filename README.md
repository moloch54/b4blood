![banner](https://user-images.githubusercontent.com/123097488/222895938-2e0568c1-71ec-4d5c-8fb8-e5122399fc33.png)  
Just a wrapper, scan and search a breach in Active Directory.  
Find Domain Controller on a network, enumerate users, AS-REP Roasting/Kerberoasting and hash cracking, bruteforce password, dump AD users, DRSUAPI, scan NFS/SMB shares for passwords, scan for remote accesses.  

Very useful for CTF's, this is a nice tool before BloodHound ingestor.  
Could be use for internal audit with these options: --internal -i eth0  


--- Installation (KALI) ---  
```sh
git clone https://github.com/moloch54/b4blood  
sudo python3 b4blood/setup.py  
```

Download kerbrute for your computer:  
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

```sh
USAGE:  
Make fisrt a folder, a lot of logs will be written.  

mkdir myfolder; cd myfolder  

b4blood --ip 192.168.0.45  
b4blood --ip 192.168.0.0/24  
b4blood --ip 192.168.0.* -U users.txt -P passwd.txt  

b4blood --internal -i eth0  
```  
  
Features:  

Scan the DC, time sync for Kerberos  
![synchro](https://user-images.githubusercontent.com/123097488/222896000-3bdea77c-2f4d-4e5b-b2ca-24814e7c912d.png)  

Kerbrute users/passwords, you can provide your own users list (-U my_userslist.txt) and/or your password list (-P passlist.txt) 
![ker](https://user-images.githubusercontent.com/123097488/222896214-a5e4d54c-d1e8-4732-bdcd-92c4b12c2c28.png)  

Check for AS-REP roasting and launch rockyou.txt against the hash  
![asrep](https://user-images.githubusercontent.com/123097488/222895707-124849b4-3303-4d23-b23e-e2c658e524ac.png)  

Dump AD
![ldap](https://user-images.githubusercontent.com/123097488/222896889-b57679de-210e-46ff-b2e4-e15baaead00b.png)  

Scan recursively SMB/NFS shares and dumping juicy files (could be long, --nsd to skip this part)
![smb_shares](https://user-images.githubusercontent.com/123097488/222895755-c1b764dc-52a8-4a49-9fdb-22ff1b862764.png)  
![smb_dump](https://user-images.githubusercontent.com/123097488/222895744-8e1cc8cd-663d-48f3-96d0-9b1b9deeb347.png)  
![NFS](https://user-images.githubusercontent.com/123097488/222895578-2566f364-8921-4f38-a464-85d474d3d1ed.png)  

Scan for .xml GPP files in SYSVOL and extract passwords  

Scan remote connections  
![ssh](https://user-images.githubusercontent.com/123097488/222895583-44424f0f-0f6e-4fce-a077-e8f38ceb8f46.png) 

Scan for Kerberoastable accounts  
![kerberostable](https://user-images.githubusercontent.com/123097488/222897588-f6be19af-f187-43af-b0a7-c1706a949ad1.png)  

Add your new creds found and relaunch b4blood  

Dump NTDS.DIT  
![ntds](https://user-images.githubusercontent.com/123097488/222900861-45b1fb57-787a-4283-920f-41a66aa3b1d0.png)  














