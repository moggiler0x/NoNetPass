# NoNetPass: разовая настройка MikroTik RouterOS 7 (сгенерировано из каталога шлюзов).
# Импорт: /import nonetpass.rsc. После импорта переместите правила NoNetPass
# ВЫШЕ правил, которые блокируют эти сервисы.
#
# У каждого шлюза свой список клиентов и свой список узлов: окно открывает
# только узлы выбранного сервиса. RouterOS 7 сам резолвит FQDN в address-list.

/ip firewall address-list
add list=nonetpass-targets-vk address=im.vk.com comment="nonetpass: VK"
add list=nonetpass-targets-vk address=api.vk.com comment="nonetpass: VK"
add list=nonetpass-targets-vk address=login.vk.com comment="nonetpass: VK"
add list=nonetpass-targets-sber-id address=api.sberbank.ru comment="nonetpass: Сбер ID"
add list=nonetpass-targets-sber-id address=securepayments.sberbank.ru comment="nonetpass: Сбер ID"
add list=nonetpass-targets-yandex-id address=passport.yandex.ru comment="nonetpass: Яндекс ID"
add list=nonetpass-targets-yandex-id address=api.passport.yandex.ru comment="nonetpass: Яндекс ID"
add list=nonetpass-targets-alfa-id address=alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-alfa-id address=click.alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-alfa-id address=api.alfabank.ru comment="nonetpass: Альфа ID"
add list=nonetpass-targets-sber-pay address=securepayments.sberbank.ru comment="nonetpass: Сбер"
add list=nonetpass-targets-sber-pay address=api.sberbank.ru comment="nonetpass: Сбер"
add list=nonetpass-targets-alfa-pay address=pay.alfabank.ru comment="nonetpass: Альфа-Банк"
add list=nonetpass-targets-alfa-pay address=click.alfabank.ru comment="nonetpass: Альфа-Банк"
add list=nonetpass-targets-vtb-pay address=3ds.vtb.ru comment="nonetpass: ВТБ"
add list=nonetpass-targets-vtb-pay address=api.vtb.ru comment="nonetpass: ВТБ"
add list=nonetpass-targets-tbank-pay address=secure.tbank.ru comment="nonetpass: Т-Банк"
add list=nonetpass-targets-tbank-pay address=api.tbank.ru comment="nonetpass: Т-Банк"

/ip firewall filter
add chain=forward action=accept src-address-list=nonetpass-clients-vk dst-address-list=nonetpass-targets-vk comment="nonetpass: окно VK (20 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-sber-id dst-address-list=nonetpass-targets-sber-id comment="nonetpass: окно Сбер ID (20 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-yandex-id dst-address-list=nonetpass-targets-yandex-id comment="nonetpass: окно Яндекс ID (20 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-alfa-id dst-address-list=nonetpass-targets-alfa-id comment="nonetpass: окно Альфа ID (20 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-sber-pay dst-address-list=nonetpass-targets-sber-pay comment="nonetpass: окно Сбер (60 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-alfa-pay dst-address-list=nonetpass-targets-alfa-pay comment="nonetpass: окно Альфа-Банк (60 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-vtb-pay dst-address-list=nonetpass-targets-vtb-pay comment="nonetpass: окно ВТБ (60 с)"
add chain=forward action=accept src-address-list=nonetpass-clients-tbank-pay dst-address-list=nonetpass-targets-tbank-pay comment="nonetpass: окно Т-Банк (60 с)"

# Отдельный пользователь с минимальными правами для NoNetPass.
/user group add name=nonetpass policy=read,write,api,rest-api
/user add name=nonetpass group=nonetpass password=CHANGE_ME address=192.168.88.0/24

# REST API (драйвер mikrotik): /ip service set www-ssl disabled=no certificate=<сертификат>
# Классический API (драйвер mikrotik-api): /ip service set api disabled=no address=192.168.88.0/24
