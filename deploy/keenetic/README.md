# Keenetic

## Вариант А: AuthPass на роутере через Entware (рекомендуется)

Нужны: USB-накопитель или встроенный Entware (KeeneticOS 4.x), компоненты
«Пакеты OPKG» и «Модули ядра подсистемы Netfilter». Модели на aarch64
(Giga KN-1011, Ultra KN-1811, Hopper, Peak и т.п.) тянут Python + FastAPI;
на MIPS-моделях используйте вариант Б.

```sh
opkg update && opkg install python3 python3-pip ipset iptables
pip3 install authpass-*.whl
cp 50-authpass.sh /opt/etc/ndm/netfilter.d/ && chmod +x /opt/etc/ndm/netfilter.d/50-authpass.sh
cp S99authpass /opt/etc/init.d/ && chmod +x /opt/etc/init.d/S99authpass
/opt/etc/init.d/S99authpass start
```

Хук `netfilter.d` вызывается прошивкой при каждой пересборке правил, поэтому
правило-окно не пропадёт. AuthPass работает с драйвером `ipset`: кладёт IP
клиента в `authpass_clients` с таймаутом и сам резолвит узлы доставки в
`authpass_targets`.

## Вариант Б: AuthPass на отдельной машине, роутер по RCI

Драйвер `keenetic` открывает окно правилами `access-list` через RCI
(`AUTHPASS_ROUTER_URL=http://192.168.1.1`, пользователь с правом доступа к
веб-интерфейсу). Изменения не сохраняются в startup-config, поэтому
перезагрузка тоже закрывает окно. Список доступа `authpass` нужно один раз
создать и привязать к сегменту в CLI так, чтобы permit-правила AuthPass
стояли перед запрещающими. Синтаксис CLI отличается между версиями
KeeneticOS; при необходимости шаблоны команд меняются через
`AUTHPASS_DRIVER_OPT_GRANT_CMD` и `AUTHPASS_DRIVER_OPT_REVOKE_CMD`
(подстановки `{acl}`, `{src}`, `{dst}`).
