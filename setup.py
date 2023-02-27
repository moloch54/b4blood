#/usr/bin/python

import os

os.system("sudo apt-get update")
os.system("sudo install -y ntpdate")
os.system("pip3 install kerbrute")
os.system("sudo git clone https://github.com/moloch54/b4blood")
os.system("sudo cp b4blood/b4blood.py /usr/bin/b4blood")
os.system("sudo chmod +x /usr/bin/b4blood")
os.system("sudo apt install -y python3-pip")
os.system("sudo git clone https://github.com/fortra/impacket /opt/impacket")
os.system("sudo apt install -y python3-impacket")
os.system("cd /opt/impacket")
os.system("sudo python3 ./setup.py install")
os.system("gunzip /usr/share/wordlists/rockyou.txt.gz")
