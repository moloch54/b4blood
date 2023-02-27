#/usr/bin/python3

import os

os.system("sudo apt-get update")
os.system("sudo install -y ntpdate")
os.system("sudo cp b4blood.py /usr/bin/b4blood")
os.system("sudo chmod +x /usr/bin/b4blood")
os.system("sudo apt install -y python3-pip")
os.system("sudo git clone https://github.com/fortra/impacket /opt/impacket")
os.system("sudo apt install -y python3-impacket")
os.system("sudo python3 /opt/impacket/setup.py install")
os.system("gunzip /usr/share/wordlists/rockyou.txt.gz")
