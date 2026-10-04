# T2 Firewall
## A rewrite of a nftable firewall created by Loop

---

### Features
 - Ratelimit packets across designated ports
 - Ratelimit new connections
 - Ban an ip, exempt an ip

---

### Use
 - install:            sudo ./t2_firewall.sh
 - uninstall:          sudo ./t2_firewall.sh off
 - show rules/counters: sudo ./t2_firewall.sh show
 - ban an ip:          sudo ./t2_firewall.sh ban 192.168.0.11
 - unban an ip:        sudo ./t2_firewall.sh unban 192.168.0.11
 - exempt an ip:       sudo ./t2_firewall.sh exempt 192.168.0.11
 - clear rate trackers: sudo ./t2_firewall.sh clear
 - clear every ban:    sudo ./t2_firewall.sh clearbans
 - save bans for reboot: sudo ./t2_firewall.sh save

---

### Prerequisites
 - sudo apt install nftables

---

## Installation
 - `sudo ./t2_firewall.sh` to activate
 - `sudo ./t2_firewall.sh off` to deactivate

----

### Credits & Thanks
 - Loop
