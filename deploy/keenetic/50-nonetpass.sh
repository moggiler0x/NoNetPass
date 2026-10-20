#!/bin/sh
# /opt/etc/ndm/netfilter.d/50-nonetpass.sh — правило-окно NoNetPass для Keenetic/Entware.
# Пары «IP клиента,IP узла шлюза» с таймаутом: окно открывает только узлы
# выбранного шлюза.
[ "$type" = "ip6tables" ] && exit 0
[ "$table" = "filter" ] || exit 0

ipset create nonetpass_pairs hash:net,net timeout 0 -exist

RULE="FORWARD -m set --match-set nonetpass_pairs src,dst -j ACCEPT"
iptables -C $RULE 2>/dev/null || iptables -I $RULE
exit 0
