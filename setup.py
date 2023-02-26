#/usr/bin/python

import os

os.system("sudo apt-get update; cd ~; sudo git clone https://github.com/moloch54/b4blood; sudo cp b4blood/b4blood.py /usr/bin/b4blood; sudo chmod +x /usr/bin/b4blood; sudo apt install -y python3-pip; sudo git clone https://github.com/fortra/impacket /opt/impacket; sudo apt install -y python3-impacket; cd /opt/impacket; sudo python3 ./setup.py install; cd /usr/share/wordlists; gunzip rockyou.txt.gz")