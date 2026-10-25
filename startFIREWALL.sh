#!/bin/sh
echo "Configuring T2 Firewall"
sudo ./t2_firewall.sh off
sudo ./t2_firewall.sh
sudo ./t2_firewall.sh clear
echo "Exempting 127.0.0.1"
sudo ./t2_firewall.sh exempt 127.0.0.1
sudo ./t2_firewall.sh save
echo "Done!"
