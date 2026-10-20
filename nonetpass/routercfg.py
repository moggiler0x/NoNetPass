"""Генерация разовой настройки роутера из каталога шлюзов.

    nonetpass router-config mikrotik  > nonetpass.rsc
    nonetpass router-config nftables  > /etc/nonetpass/sets.nft
    nonetpass router-config ipset     > /opt/etc/ndm/netfilter.d/50-nonetpass.sh
"""

from __future__ import annotations

from .drivers import PAIRS_SET
from .drivers.mikrotik import gate_list
from .gates import GateCatalog


def mikrotik(catalog: GateCatalog, client_list: str = "nonetpass-clients") -> str:
    lines = [
        "# NoNetPass: разовая настройка MikroTik RouterOS 7 (сгенерировано из каталога шлюзов).",
        "# Импорт: /import nonetpass.rsc. После импорта переместите правила NoNetPass",
        "# ВЫШЕ правил, которые блокируют эти сервисы.",
        "#",
        "# У каждого шлюза свой список клиентов и свой список узлов: окно открывает",
        "# только узлы выбранного сервиса. RouterOS 7 сам резолвит FQDN в address-list.",
        "",
        "/ip firewall address-list",
    ]
    for gate in catalog.all:
        for host in gate.targets:
            lines.append(
                f'add list={gate_list("nonetpass-targets", gate.id)} address={host} '
                f'comment="nonetpass: {gate.name}"'
            )
    lines += ["", "/ip firewall filter"]
    for gate in catalog.all:
        lines.append(
            f"add chain=forward action=accept src-address-list={gate_list(client_list, gate.id)} "
            f'dst-address-list={gate_list("nonetpass-targets", gate.id)} '
            f'comment="nonetpass: окно {gate.name} ({int(gate.window)} с)"'
        )
    lines += [
        "",
        "# Отдельный пользователь с минимальными правами для NoNetPass.",
        "/user group add name=nonetpass policy=read,write,api,rest-api",
        "/user add name=nonetpass group=nonetpass password=CHANGE_ME address=192.168.88.0/24",
        "",
        "# REST API (драйвер mikrotik): /ip service set www-ssl disabled=no certificate=<сертификат>",
        "# Классический API (драйвер mikrotik-api): /ip service set api disabled=no address=192.168.88.0/24",
    ]
    return "\n".join(lines) + "\n"


def nftables(catalog: GateCatalog) -> str:
    return (
        "# /etc/nonetpass/sets.nft — подключается в таблицу inet fw4 (position table-pre).\n"
        "# Пары «IP клиента . IP узла шлюза» с таймаутом: окно открывает только\n"
        "# узлы выбранного шлюза.\n"
        f"set {PAIRS_SET} {{\n"
        "    type ipv4_addr . ipv4_addr\n"
        "    flags timeout\n"
        "}\n"
    )


def ipset(catalog: GateCatalog) -> str:
    return (
        "#!/bin/sh\n"
        "# /opt/etc/ndm/netfilter.d/50-nonetpass.sh — правило-окно NoNetPass для Keenetic/Entware.\n"
        "# Пары «IP клиента,IP узла шлюза» с таймаутом: окно открывает только узлы\n"
        "# выбранного шлюза.\n"
        '[ "$type" = "ip6tables" ] && exit 0\n'
        '[ "$table" = "filter" ] || exit 0\n'
        "\n"
        f"ipset create {PAIRS_SET} hash:net,net timeout 0 -exist\n"
        "\n"
        f'RULE="FORWARD -m set --match-set {PAIRS_SET} src,dst -j ACCEPT"\n'
        "iptables -C $RULE 2>/dev/null || iptables -I $RULE\n"
        "exit 0\n"
    )


GENERATORS = {"mikrotik": mikrotik, "nftables": nftables, "ipset": ipset}
