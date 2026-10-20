# OpenWrt 22.03+ (fw4 / nftables)

## Общая часть: наборы и правило

```sh
mkdir -p /etc/nonetpass
cp nonetpass.nft /etc/nonetpass/sets.nft
cp nonetpass-rule.nft /etc/nonetpass/rule.nft
cat firewall.uci >> /etc/config/firewall
fw4 reload
```

## Вариант А: NoNetPass на самом роутере

Подходит для arm64/x86 с ≥256 МБ ОЗУ (FastAPI требует pydantic-core,
под MIPS готовых сборок нет, там используйте вариант Б).

```sh
opkg update && opkg install python3 python3-pip
pip3 install nonetpass-*.whl          # или pip3 install . из исходников
cp nonetpass.init /etc/init.d/nonetpass && chmod +x /etc/init.d/nonetpass
# детекция по DNS: логирование запросов dnsmasq
uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/var/log/dnsmasq.log'
uci commit dhcp && /etc/init.d/dnsmasq restart
/etc/init.d/nonetpass enable && /etc/init.d/nonetpass start
```

## Вариант Б: NoNetPass на отдельной машине, роутер по ubus

```sh
opkg install uhttpd-mod-ubus rpcd
cp nonetpass.acl.json /usr/share/rpcd/acl.d/nonetpass.json
# пользователь rpcd
uci add rpcd login
uci set rpcd.@login[-1].username='nonetpass'
uci set rpcd.@login[-1].password="$(uhttpd -m 'CHANGE_ME')"
uci add_list rpcd.@login[-1].read='nonetpass'
uci add_list rpcd.@login[-1].write='nonetpass'
uci commit rpcd && /etc/init.d/rpcd restart
```

На машине с NoNetPass: `NONETPASS_DRIVER=openwrt NONETPASS_ROUTER_URL=https://192.168.1.1
NONETPASS_ROUTER_USER=nonetpass NONETPASS_ROUTER_PASSWORD=CHANGE_ME`.
Узлы шлюзов резолвит машина с NoNetPass и кладёт в набор `nonetpass_pairs`
пары «IP клиента . IP узла» с таймаутом, поэтому окно открывает только узлы
выбранного шлюза.
