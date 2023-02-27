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
Download kerbrute for your computer:  
https://github.com/ropnop/kerbrute/releases  
rename it to "kerbrute" and place it in /usr/bin  
sudo chmod +x /bin/usr/kerbrute  


Installation (UBUNTU):  
```sh
git clone https://github.com/moloch54/b4blood  
sudo python3 b4blood/setup.py 
sudo snap install crackmapexec    
sudo apt install smbmap  
sudo apt install smbclient  
sudo mkdir -p /usr/share/wordlists  
sudo mkdir -p /usr/share/wordlists/seclists/Usernames   
```  
Download kerbrute for your computer:  
https://github.com/ropnop/kerbrute/releases  
Rename it to "kerbrute"  

```sh
cd ~/Downloads
sudo cp kerbrute /usr/bin
sudo chmod +x /bin/usr/kerbrute  
```


| :warning: WARNING                                     |
|:------------------------------------------------------|
|rockyou.txt must be in /usr/share/wordlists/rockyou.txt|  
|xato-net-10-million-usernames must be in /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt| 


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

