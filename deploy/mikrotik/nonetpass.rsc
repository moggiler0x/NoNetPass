# NoNetPass для MikroTik с Captive Portal провайдера (Hotspot + RADIUS).
# Сгенерировано: nonetpass router-config mikrotik. Импорт: /import nonetpass.rsc
#
# Выполняется ПОСЛЕ шагов 1-6 инструкции провайдера: bridge-hotspot,
# сеть 192.168.110.0/24, /ip hotspot setup, RADIUS и walled garden страниц входа.
# Страницы входа (id.vk.ru, id.sber.ru, passport.yandex.ru, ...) провайдер
# открывает в walled garden всегда. NoNetPass дополнительно и только на время
# окна открывает узлы, через которые приходит код или подтверждение оплаты.

# 1. Узлы каждого шлюза. RouterOS 7 сам резолвит FQDN в address-list.
/ip firewall address-list
add list=nonetpass-targets-vk address=api.vk.ru comment="nonetpass: VK ID"
add list=nonetpass-targets-vk address=api.vk.com comment="nonetpass: VK ID"
add list=nonetpass-targets-vk address=login.vk.ru comment="nonetpass: VK ID"
add list=nonetpass-targets-vk address=login.vk.com comment="nonetpass: VK ID"
add list=nonetpass-targets-vk address=im.vk.com comment="nonetpass: VK ID"
add list=nonetpass-targets-sber-id address=online.sberbank.ru comment="nonetpass: Сбер ID"
add list=nonetpass-targets-sber-id address=api.sberbank.ru comment="nonetpass: Сбер ID"
add list=nonetpass-targets-yandex-id address=api.passport.yandex.ru comment="nonetpass: Яндекс ID"
add list=nonetpass-targets-yandex-id address=push.yandex.ru comment="nonetpass: Яндекс ID"
add list=nonetpass-targets-yandex-id address=id.yandex.ru comment="nonetpass: Яндекс ID"
add list=nonetpass-targets-alfa-id address=online.alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-alfa-id address=click.alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-alfa-id address=api.alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-gosuslugi address=lk.gosuslugi.ru comment="nonetpass: Госуслуги"
add list=nonetpass-targets-gosuslugi address=api.gosuslugi.ru comment="nonetpass: Госуслуги"
add list=nonetpass-targets-gosuslugi address=gu-st.ru comment="nonetpass: Госуслуги"
add list=nonetpass-targets-sber-pay address=securepayments.sberbank.ru comment="nonetpass: Сбер"
add list=nonetpass-targets-sber-pay address=api.sberbank.ru comment="nonetpass: Сбер"
add list=nonetpass-targets-alfa-pay address=pay.alfabank.ru comment="nonetpass: Альфа-Банк"
add list=nonetpass-targets-alfa-pay address=click.alfabank.ru comment="nonetpass: Альфа-Банк"
add list=nonetpass-targets-vtb-pay address=3ds.vtb.ru comment="nonetpass: ВТБ"
add list=nonetpass-targets-vtb-pay address=api.vtb.ru comment="nonetpass: ВТБ"
add list=nonetpass-targets-tbank-pay address=secure.tbank.ru comment="nonetpass: Т-Банк"
add list=nonetpass-targets-tbank-pay address=api.tbank.ru comment="nonetpass: Т-Банк"

# 2. Окна для клиентов, ещё не прошедших вход в Hotspot. Hotspot перехватывает
#    их трафик раньше /ip firewall filter, поэтому пропуск делается через
#    walled garden ip. NoNetPass кладёт IP клиента в nonetpass-clients-<шлюз>
#    с timeout, и роутер сам закроет окно даже без NoNetPass.
/ip hotspot walled-garden ip
add action=accept server=hotspot1 src-address-list=nonetpass-clients-vk dst-address-list=nonetpass-targets-vk comment="nonetpass: окно VK ID (120 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-sber-id dst-address-list=nonetpass-targets-sber-id comment="nonetpass: окно Сбер ID (120 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-yandex-id dst-address-list=nonetpass-targets-yandex-id comment="nonetpass: окно Яндекс ID (120 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-alfa-id dst-address-list=nonetpass-targets-alfa-id comment="nonetpass: окно Альфа ID (120 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-gosuslugi dst-address-list=nonetpass-targets-gosuslugi comment="nonetpass: окно Госуслуги (120 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-sber-pay dst-address-list=nonetpass-targets-sber-pay comment="nonetpass: окно Сбер (300 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-alfa-pay dst-address-list=nonetpass-targets-alfa-pay comment="nonetpass: окно Альфа-Банк (300 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-vtb-pay dst-address-list=nonetpass-targets-vtb-pay comment="nonetpass: окно ВТБ (300 с)"
add action=accept server=hotspot1 src-address-list=nonetpass-clients-tbank-pay dst-address-list=nonetpass-targets-tbank-pay comment="nonetpass: окно Т-Банк (300 с)"

# 3. Портал NoNetPass доступен до входа в Hotspot.
add action=accept server=hotspot1 dst-address=172.17.0.2 protocol=tcp dst-port=8080 comment="nonetpass: портал"
/ip dns static
add name=nonetpass.lan address=172.17.0.2 comment="nonetpass: портал"

# 4. Для клиентов, уже прошедших вход: если провайдер или вы закрываете
#    эти сервисы в forward, правила ниже открывают окно и для них.
#    Переместите их выше запрещающих правил.
/ip firewall filter
add chain=forward action=accept src-address-list=nonetpass-clients-vk dst-address-list=nonetpass-targets-vk comment="nonetpass: окно VK ID"
add chain=forward action=accept src-address-list=nonetpass-clients-sber-id dst-address-list=nonetpass-targets-sber-id comment="nonetpass: окно Сбер ID"
add chain=forward action=accept src-address-list=nonetpass-clients-yandex-id dst-address-list=nonetpass-targets-yandex-id comment="nonetpass: окно Яндекс ID"
add chain=forward action=accept src-address-list=nonetpass-clients-alfa-id dst-address-list=nonetpass-targets-alfa-id comment="nonetpass: окно Альфа ID"
add chain=forward action=accept src-address-list=nonetpass-clients-gosuslugi dst-address-list=nonetpass-targets-gosuslugi comment="nonetpass: окно Госуслуги"
add chain=forward action=accept src-address-list=nonetpass-clients-sber-pay dst-address-list=nonetpass-targets-sber-pay comment="nonetpass: окно Сбер"
add chain=forward action=accept src-address-list=nonetpass-clients-alfa-pay dst-address-list=nonetpass-targets-alfa-pay comment="nonetpass: окно Альфа-Банк"
add chain=forward action=accept src-address-list=nonetpass-clients-vtb-pay dst-address-list=nonetpass-targets-vtb-pay comment="nonetpass: окно ВТБ"
add chain=forward action=accept src-address-list=nonetpass-clients-tbank-pay dst-address-list=nonetpass-targets-tbank-pay comment="nonetpass: окно Т-Банк"

# 5. NoNetPass должен видеть настоящий IP клиента. /ip hotspot setup
#    добавляет masquerade для 192.168.110.0/24, поэтому трафик к порталу
#    исключаем из него (правило ставится первым в srcnat).
/ip firewall nat
add chain=srcnat src-address=192.168.110.0/24 dst-address=172.17.0.2 action=accept place-before=0 comment="nonetpass: без masquerade к порталу"

# 6. Доступ NoNetPass к роутеру. Инструкция провайдера отключает api и
#    api-ssl, поэтому NoNetPass работает через REST (драйвер mikrotik, служба
#    www-ssl). Пускаем к ней только адрес NoNetPass. Право reboot нужно
#    для перезагрузки роутера из админ-панели и Telegram-бота.
#    Замените CHANGE_ME на свой пароль до импорта.
/user group add name=nonetpass policy=read,write,api,rest-api,reboot
/user add name=nonetpass group=nonetpass password=CHANGE_ME address=172.17.0.2/32
/certificate add name=nonetpass-rest common-name=nonetpass-rest days-valid=3650
/certificate sign nonetpass-rest
/ip service set www-ssl disabled=no certificate=nonetpass-rest address=172.17.0.2/32
