#!/bin/sh
# /opt/etc/ndm/netfilter.d/50-authpass.sh — правило-окно AuthPass для Keenetic/Entware.
[ "$type" = "ip6tables" ] && exit 0
[ "$table" = "filter" ] || exit 0

ipset create authpass_clients hash:ip timeout 0 -exist
ipset create authpass_targets hash:ip timeout 0 -exist

RULE="FORWARD -m set --match-set authpass_clients src -m set --match-set authpass_targets dst -j ACCEPT"
iptables -C $RULE 2>/dev/null || iptables -I $RULE
exit 0
