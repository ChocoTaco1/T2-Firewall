#!/bin/bash
#
# Tribes 2 UDP crasher/flood filter. One nft table, one port range.
#
#   install:            sudo ./t2_firewall.sh
#   uninstall:          sudo ./t2_firewall.sh off
#   show rules/counters: sudo ./t2_firewall.sh show
#   ban an ip:          sudo ./t2_firewall.sh ban 192.168.0.11
#   unban an ip:        sudo ./t2_firewall.sh unban 192.168.0.11
#   exempt an ip:       sudo ./t2_firewall.sh exempt 192.168.0.11
#   clear rate trackers: sudo ./t2_firewall.sh clear
#   clear every ban:    sudo ./t2_firewall.sh clearbans
#   save bans for reboot: sudo ./t2_firewall.sh save
#
# Errata:
# 1. nft missing on debian even though `iptables -L` says (nf_tables):
#      sudo apt install -y nftables && sudo systemctl enable nftables
# 2. if a banned IP comes straight back, they are still running the crasher.
# 3. PER_PORT_LIMIT=1 needs nft >= 0.9.1 / kernel >= 5.6 (debian 11+, ubuntu 20.04+).
#    Set it to 0 on anything older.

set -u

##############################################################################
## Config
##############################################################################

# Server ports. Anything nft accepts as a dport expression:
#   PORTS="28000-28008"
#   PORTS="{ 28000-28004, 28010, 28020-28022 }"
#   PORTS="28000"
PORTS="28000-28008"

TABLE="tribes2"
CHAIN="bitcrusher"

## Limits
# New connections per second (an IP not seen within the conntrack timeout)
NEW_LIMIT="5/second"
# Harsher long window limit, e.g. "20/minute". Empty disables the rule.
NEW_LIMIT_HARSH=""
# Maximum packets per second from one IP
# Multiple players behind one IP share this budget, so exempt them if needed.
TICK_LIMIT="128/second"

# 1 = every port gets its own budget per IP (what the nine per-port scripts did)
# 0 = one budget per IP shared across every port in PORTS
PER_PORT_LIMIT=1

# Rate tracking sets: how long an idle IP is remembered, and the element cap.
# The cap is what stops a spoofed-source flood from eating memory.
TRACK_TIMEOUT="1m"
TRACK_SIZE=65535
# Ban length, e.g. "1h". Empty means until you unban by hand.
BAN_TIMEOUT=""
BAN_SIZE=65535

# Persist across reboots by including our table from /etc/nftables.conf
PERSIST=1

INFO=""            # set to anything to add counter-only diagnostic rules
COUNTER="counter"  # blank this to drop the per-rule counters

##############################################################################
## Guts
##############################################################################

if (( PER_PORT_LIMIT )); then
	KEY="ipv4_addr . inet_service"   # set key type
	ELEM="ip saddr . udp dport"      # what a rule puts in the set
else
	KEY="ipv4_addr"
	ELEM="ip saddr"
fi

# every port rule starts the same way. $PORTS and $COUNTER stay unquoted so a
# brace list splits into separate argv entries, which nft joins back together.
rule() { nft add rule ip $TABLE $CHAIN udp dport $PORTS "$@"; }

function create() {
	nft add table ip $TABLE
	# Holy crap this thing is persnickety with argument ordering
	nft "add chain ip $TABLE $CHAIN { type filter hook input priority 0; policy accept; }"

	# Known-good IPs skip every limit below (LAN hosts, a house with 4 players)
	nft "add set ip $TABLE exempt { type ipv4_addr; flags interval; }"
	nft add rule ip $TABLE $CHAIN ip saddr @exempt $COUNTER return

	# Malformed packets land their sender here, dropped before any other counter
	if [[ -n $BAN_TIMEOUT ]]; then
		nft "add set ip $TABLE evil_tracker { type ipv4_addr; flags dynamic,timeout; timeout $BAN_TIMEOUT; size $BAN_SIZE; }"
	else
		nft "add set ip $TABLE evil_tracker { type ipv4_addr; flags dynamic; size $BAN_SIZE; }"
	fi
	nft add rule ip $TABLE $CHAIN ip saddr @evil_tracker $COUNTER drop

	# Informational rules, enable with INFO
	if [[ -n $INFO ]]; then
		rule $COUNTER
		rule ct state new $COUNTER
	fi

	# Single byte payloads are not game packets (udp length counts the 8 byte
	# header). Sender gets blacklisted.
	rule udp length 9 add @evil_tracker "{ ip saddr }" $COUNTER drop

	# Connection flood, counted per IP
	nft "add set ip $TABLE conn_tracker { type $KEY; flags dynamic,timeout; timeout $TRACK_TIMEOUT; size $TRACK_SIZE; }"
	rule ct state new add @conn_tracker "{ $ELEM limit rate over $NEW_LIMIT }" $COUNTER drop
	if [[ -n $NEW_LIMIT_HARSH ]]; then
		nft "add set ip $TABLE conn_tracker_harsh { type $KEY; flags dynamic,timeout; timeout $TRACK_TIMEOUT; size $TRACK_SIZE; }"
		rule ct state new add @conn_tracker_harsh "{ $ELEM limit rate over $NEW_LIMIT_HARSH }" $COUNTER drop
	fi

	# Packet flood, counted per IP. Covers most single connection angles.
	nft "add set ip $TABLE tick_tracker { type $KEY; flags dynamic,timeout; timeout $TRACK_TIMEOUT; size $TRACK_SIZE; }"
	rule add @tick_tracker "{ $ELEM limit rate over $TICK_LIMIT }" $COUNTER drop
}

function reset() {
	# not existing yet is not an error worth printing
	nft delete table ip $TABLE 2>/dev/null
	# drop the old one-table-per-port layout if it is still loaded
	for t in $(nft list tables ip 2>/dev/null | awk -v p="${TABLE}_" '$3 ~ "^"p {print $3}'); do
		nft delete table ip "$t"
	done
}

function clear_sets() {
	nft flush set ip $TABLE tick_tracker
	nft flush set ip $TABLE conn_tracker
	if [[ -n $NEW_LIMIT_HARSH ]]; then
		nft flush set ip $TABLE conn_tracker_harsh
	fi
}

function forget_at_startup() {
	[[ -f /etc/nftables.conf ]] || return 0
	# leaving the include behind would break the whole ruleset load at next boot
	sed -i.t2bak '\|^include "/etc/nftables_t2.conf"$|d' /etc/nftables.conf
	rm -f /etc/nftables_t2.conf
}

function restore_at_startup() {
	local add="include \"/etc/nftables_t2.conf\""
	if [[ ! -f /etc/nftables.conf ]]; then
		echo "Expected file at /etc/nftables.conf to add '$add'"
		exit 1
	fi
	grep -Fq "$add" /etc/nftables.conf || echo "$add" >> /etc/nftables.conf
	# dump our table only, so other ip tables are left alone, and make the
	# include reloadable by clearing the table first
	{
		echo "table ip $TABLE { }"
		echo "delete table ip $TABLE"
		nft -s list table ip $TABLE
	} > /etc/nftables_t2.conf
}

##############################################################################
## cmdline
##############################################################################

case "${1:-on}" in
	on)
		reset
		create
		if (( PERSIST )); then restore_at_startup; fi
		;;
	off)
		reset
		forget_at_startup
		;;
	show)      nft list table ip $TABLE ;;
	save)      restore_at_startup ;;
	clear)     clear_sets ;;
	clearbans) nft flush set ip $TABLE evil_tracker ;;
	ban)       nft add element ip $TABLE evil_tracker "{ ${2:?missing IP: $0 ban 1.2.3.4} }" ;;
	unban)     nft delete element ip $TABLE evil_tracker "{ ${2:?missing IP: $0 unban 1.2.3.4} }" ;;
	exempt)    nft add element ip $TABLE exempt "{ ${2:?missing IP: $0 exempt 1.2.3.4} }" ;;
	unexempt)  nft delete element ip $TABLE exempt "{ ${2:?missing IP: $0 unexempt 1.2.3.4} }" ;;
	# bare IP: the old script's unban shorthand
	[0-9]*.[0-9]*) nft delete element ip $TABLE evil_tracker "{ $1 }" ;;
	*)
		echo "usage: $0 [on|off|show|save|clear|clearbans]"
		echo "       $0 [ban|unban|exempt|unexempt] <ip>"
		exit 1
		;;
esac
