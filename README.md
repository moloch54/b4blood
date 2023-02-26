# b4blood
Just a wrapper, scan and search a breach in Active Directory.
Find Domain Controller on a network, enumerate users, AS-REP Roasting and hash cracking, bruteforce password, dump AD users, scan SMB shares for passwords.
Very useful in CTF, this is a nice tool before BloodHound ingestor.

--internal options for real life.

You need impacket: 
https://blog.eldernode.com/install-and-use-impacket-on-kali-linux/

also:
nmap, crackmapexec, smbmap, smbclient, ldapdump
should be fine on Kali

rockyou.txt must be in /usr/share/wordlists/rockyou.txt

You need to specifie line 11 YOUR own path for impacket/examples: 
path_impacket="/opt/impacket/examples"

