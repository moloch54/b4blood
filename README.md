# b4blood
Just a wrapper, scan and search a breach in Active Directory.  
Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, DRSUAPI, scan SMB shares for passwords.  

Very useful for CTF's, this is a nice tool before BloodHound ingestor.  
Could be use for internal audit with this option: --internal


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
mkdir /usr/share/wordlists  
```  

rockyou.txt must be in /usr/share/wordlists/rockyou.txt

If Impacket is already installed, you need to specifie line 11 YOUR own path for impacket/examples:   
path_impacket="/opt/impacket/examples"  

USAGE:  

b4blood IP <OPTIONS>
b4blood 192.168.0.45  
b4blood 192.168.0.0/24 -U users.txt -P passwd.txt  
b4blood --internal -i eth0  


