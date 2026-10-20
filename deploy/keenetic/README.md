# Keenetic

## Вариант А: NoNetPass на роутере через Entware (рекомендуется)

Нужны: USB-накопитель или встроенный Entware (KeeneticOS 4.x), компоненты
«Пакеты OPKG» и «Модули ядра подсистемы Netfilter». Модели на aarch64
(Giga KN-1011, Ultra KN-1811, Hopper, Peak и т.п.) тянут Python + FastAPI;
на MIPS-моделях используйте вариант Б.

```sh
opkg update && opkg install python3 python3-pip ipset iptables
pip3 install nonetpass-*.whl
cp 50-nonetpass.sh /opt/etc/ndm/netfilter.d/ && chmod +x /opt/etc/ndm/netfilter.d/50-nonetpass.sh
cp S99nonetpass /opt/etc/init.d/ && chmod +x /opt/etc/init.d/S99nonetpass
/opt/etc/init.d/S99nonetpass start
```

Хук `netfilter.d` вызывается прошивкой при каждой пересборке правил, поэтому
правило-окно не пропадёт. NoNetPass работает с драйвером `ipset`: резолвит
узлы выбранного шлюза и кладёт в набор `nonetpass_pairs` пары «IP клиента,IP
узла» с таймаутом, поэтому окно открывает только узлы этого шлюза. Хук
генерируется командой `nonetpass router-config ipset`.

## Вариант Б: NoNetPass на отдельной машине, роутер по RCI

Драйвер `keenetic` открывает окно правилами `access-list` через RCI
(`NONETPASS_ROUTER_URL=http://192.168.1.1`, пользователь с правом доступа к
веб-интерфейсу). Изменения не сохраняются в startup-config, поэтому
перезагрузка тоже закрывает окно. Список доступа `nonetpass` нужно один раз
создать и привязать к сегменту в CLI так, чтобы permit-правила NoNetPass
стояли перед запрещающими. Синтаксис CLI отличается между версиями
KeeneticOS; при необходимости шаблоны команд меняются через
`NONETPASS_DRIVER_OPT_GRANT_CMD` и `NONETPASS_DRIVER_OPT_REVOKE_CMD`
(подстановки `{acl}`, `{src}`, `{dst}`).
