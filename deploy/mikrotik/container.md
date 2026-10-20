# AuthPass в контейнере на MikroTik (RouterOS 7, arm64/x86)

Нужен пакет `container`, внешний носитель (USB/диск) и включённый режим
контейнеров (`/system/device-mode/update container=yes`, подтверждение кнопкой).

```
/interface veth add name=veth-authpass address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge add name=containers
/ip address add address=172.17.0.1/24 interface=containers
/interface bridge port add bridge=containers interface=veth-authpass

/container envs
add name=authpass key=AUTHPASS_DRIVER value=mikrotik
add name=authpass key=AUTHPASS_ROUTER_URL value=https://172.17.0.1
add name=authpass key=AUTHPASS_ROUTER_USER value=authpass
add name=authpass key=AUTHPASS_ROUTER_PASSWORD value=CHANGE_ME
add name=authpass key=AUTHPASS_ROUTER_VERIFY_TLS value=false
add name=authpass key=AUTHPASS_TRUST_FORWARDED value=false

/container add file=usb1/authpass.tar interface=veth-authpass envlist=authpass \
    root-dir=usb1/authpass start-on-boot=yes logging=yes
/container start [find interface=veth-authpass]

# Панель для клиентов LAN: dst-nat на контейнер.
# src-nat здесь не нужен: AuthPass должен видеть реальный IP клиента.
/ip firewall nat add chain=dstnat dst-address=192.168.88.1 protocol=tcp dst-port=8080 \
    action=dst-nat to-addresses=172.17.0.2 to-ports=8080 comment="authpass panel"
```

Образ собирается из `Dockerfile` в корне репозитория:
`docker buildx build --platform linux/arm64 -t authpass . && docker save authpass > authpass.tar`.
