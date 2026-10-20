# OpenWrt 22.03+ (fw4 / nftables)

## Общая часть: наборы и правило

```sh
mkdir -p /etc/authpass
cp authpass.nft /etc/authpass/sets.nft
cp authpass-rule.nft /etc/authpass/rule.nft
cat firewall.uci >> /etc/config/firewall
fw4 reload
```

## Вариант А: AuthPass на самом роутере

Подходит для arm64/x86 с ≥256 МБ ОЗУ (FastAPI требует pydantic-core,
под MIPS готовых сборок нет, там используйте вариант Б).

```sh
opkg update && opkg install python3 python3-pip
pip3 install authpass-*.whl          # или pip3 install . из исходников
cp authpass.init /etc/init.d/authpass && chmod +x /etc/init.d/authpass
# детекция по DNS: логирование запросов dnsmasq
uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/var/log/dnsmasq.log'
uci commit dhcp && /etc/init.d/dnsmasq restart
/etc/init.d/authpass enable && /etc/init.d/authpass start
```

## Вариант Б: AuthPass на отдельной машине, роутер по ubus

```sh
opkg install uhttpd-mod-ubus rpcd
cp authpass.acl.json /usr/share/rpcd/acl.d/authpass.json
# пользователь rpcd
uci add rpcd login
uci set rpcd.@login[-1].username='authpass'
uci set rpcd.@login[-1].password="$(uhttpd -m 'CHANGE_ME')"
uci add_list rpcd.@login[-1].read='authpass'
uci add_list rpcd.@login[-1].write='authpass'
uci commit rpcd && /etc/init.d/rpcd restart
```

На машине с AuthPass: `AUTHPASS_DRIVER=openwrt AUTHPASS_ROUTER_URL=https://192.168.1.1
AUTHPASS_ROUTER_USER=authpass AUTHPASS_ROUTER_PASSWORD=CHANGE_ME`.
Набор узлов доставки в этом режиме заполняет dnsmasq роутера:

```sh
echo 'nftset=/im.vk.com/api.vk.com/4#inet#fw4#authpass_targets' > /tmp/dnsmasq.d/authpass.conf
/etc/init.d/dnsmasq restart
```
