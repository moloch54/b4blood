# b4blood
Just a wrapper, scan and search a breach in Active Directory.  
Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, scan SMB shares for passwords.  

Very useful in CTF, this is a nice tool before BloodHound ingestor.  

--internal options for real life.


Installation:  

git clone https://github.com/moloch54/b4blood  
cd b4blood  
sudo python3 setup.py  



also:  
crackmapexec, smbmap, smbclient. Should be fine on Kali.
Ubuntu:  
sudo snap crackmapexec  
sudo snap smbmap  
sudo snap smbclient  
mkdir /usr/share/wordlists

rockyou.txt must be in /usr/share/wordlists/rockyou.txt

You need to specifie line 11 YOUR own path for impacket/examples:   
path_impacket="/opt/impacket/examples"

