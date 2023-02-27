#/usr/bin/python3

import os

os.system("sudo apt update")
os.system("sudo install -y ntpdate")
os.system("sudo cp b4blood.py /usr/bin/b4blood")
os.system("sudo chmod +x /usr/bin/b4blood")
os.system("sudo git clone https://github.com/fortra/impacket /opt/impacket")
os.system("sudo apt install python3-impacket")
os.system("cd /opt/impacket/ && python3 ./setup.py install")
if not os.path.isfile("/usr/share/wordlists/rockyou.txt"):
    os.system("gunzip /usr/share/wordlists/rockyou.txt.gz")
