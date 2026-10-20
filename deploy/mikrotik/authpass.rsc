# AuthPass: разовая настройка MikroTik RouterOS 7.
# Импорт: /import authpass.rsc  (поправьте адреса и интерфейсы под свою сеть)

# Узлы доставки кода. RouterOS 7 сам резолвит FQDN в address-list
# и обновляет IP по TTL записи DNS.
/ip firewall address-list
add list=authpass-targets address=im.vk.com comment="authpass: доставка кода"
add list=authpass-targets address=api.vk.com comment="authpass: доставка кода"

# Правило-окно. После импорта переместите его ВЫШЕ правил, блокирующих VK.
# В authpass-clients AuthPass кладёт IP клиента с timeout, поэтому
# окно закроется и без AuthPass.
/ip firewall filter
add chain=forward action=accept src-address-list=authpass-clients \
    dst-address-list=authpass-targets comment="authpass: JIT окно"

# Если VK блокируется ещё и на уровне DNS (static/adlist), разрешите
# резолв узлов доставки, иначе окно откроется, но имя не разрешится.

# Отдельный пользователь с минимальными правами для AuthPass.
/user group
add name=authpass policy=read,write,api,rest-api
/user
add name=authpass group=authpass password=CHANGE_ME address=192.168.88.0/24

# REST API (драйвер mikrotik) работает через службу www-ssl:
#   /ip service set www-ssl disabled=no certificate=<ваш сертификат>
# Классический API (драйвер mikrotik-api, RouterOS 6 и 7):
#   /ip service set api disabled=no address=192.168.88.0/24
