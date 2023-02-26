# b4blood
Just a wrapper, scan and search a breach in Active Directory.  
Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, DRSUAPI, scan SMB shares for passwords, scan for remote accesses.  

Very useful for CTF's, this is a nice tool before BloodHound ingestor.  
Could be use for internal audit with this option: --internal -i eth0  


Installation (KALI):  
```sh
git clone https://github.com/moloch54/b4blood  
sudo python3 b4blood/setup.py  
```  

Installation (UBUNTU):  
```sh
git clone https://github.com/moloch54/b4blood  
sudo python3 b4blood/setup.py 
sudo snap install crackmapexec    
sudo apt install smbmap  
sudo apt install smbclient  
sudo mkdir /usr/share/wordlists  
```  
To download rockyou.txt:  
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwiKtJWIqrT9AhVFSaQEHUPZDoEQFnoECBIQAQ&url=https%3A%2F%2Fgithub.com%2Fbrannondorsey%2Fnaive-hashcat%2Freleases%2Fdownload%2Fdata%2Frockyou.txt&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd  

| :warning: WARNING                                     |
|:------------------------------------------------------|
|rockyou.txt must be in /usr/share/wordlists/rockyou.txt|


| :warning: WARNING2                                                                                                      |
| :-----------------------------------------------------------------------------------------------------------------------|
|If Impacket is already installed, you need to specifie line 11 in /usr/bin/b4blood YOUR own path for impacket/examples:  |   
path_impacket="/opt/impacket/examples"                                                                                    |

```sh
USAGE:  

b4blood IP <OPTIONS>
b4blood 192.168.0.45  
b4blood 192.168.0.0/24 -U users.txt -P passwd.txt  
b4blood --internal -i eth0  
```  

