# MikroTik с Captive Portal провайдера

Эта настройка опирается на инструкцию провайдера Captive Portal
(«Настройка Captive-portal на устройстве Mikrotik», сценарий «только
авторизация»: Hotspot + RADIUS, страница входа провайдера). Сначала
роутер настраивается строго по инструкции провайдера, потом поверх неё
добавляется NoNetPass. В настройки провайдера NoNetPass не вмешивается:
RADIUS, профили Hotspot, страницы `login.html` и walled garden страниц входа
остаются как есть.

## Как NoNetPass вписывается в схему провайдера

| Что | У провайдера | Что добавляет NoNetPass |
|---|---|---|
| Сеть гостей | `bridge-hotspot`, `192.168.110.0/24`, сервер `hotspot1` | ничего не меняет |
| Страницы входа | walled garden: `id.vk.ru`, `id.sber.ru`, `passport.yandex.ru`, `oauth.yandex.ru`, `id.alfabank.ru`, `*.gosuslugi.ru` | ничего не меняет, это узлы-триггеры шлюзов |
| Доставка кода | закрыта | окно 20 с через `walled-garden ip` только для IP устройства и только к узлам выбранного сервиса |
| Оплата | закрыта | окно 60 с так же |
| Доступ к роутеру | службы `api` и `api-ssl` отключены | драйвер `mikrotik` через REST (`www-ssl`), только с адреса NoNetPass |
| Портал NoNetPass | — | открыт до входа через walled garden, имя `nonetpass.lan` |

Почему `walled-garden ip`, а не `/ip firewall filter`: Hotspot перехватывает
трафик клиентов, ещё не прошедших вход, раньше обычных правил файрвола.
Пропустить такой трафик можно только через walled garden. NoNetPass кладёт IP
клиента в список `nonetpass-clients-<шлюз>` с таймаутом, а правило walled
garden ip пропускает этот список к списку узлов шлюза. Таймаут держит сам
роутер, поэтому окно закроется даже без NoNetPass.

## Шаги 1–6: инструкция провайдера

Выполните их как есть: мост `bridge-hotspot`, адрес `192.168.110.1/24`,
RADIUS-серверы провайдера, `/ip hotspot setup`, таймауты и профили,
walled garden страниц входа, замена файлов `login.html` и других, настройки
безопасности (в том числе `/ip service disable api,api-ssl`), NTP и имя
устройства.

## Шаг 7: контейнер NoNetPass на роутере

Нужны RouterOS 7, пакет `container`, внешний носитель (USB/диск) и режим
контейнеров (`/system/device-mode/update container=yes`, подтверждение
кнопкой на роутере).

```
/interface veth add name=veth-nonetpass address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge add name=containers
/ip address add address=172.17.0.1/24 interface=containers
/interface bridge port add bridge=containers interface=veth-nonetpass

/container envs
add name=nonetpass key=NONETPASS_DRIVER value=mikrotik
add name=nonetpass key=NONETPASS_ROUTER_URL value=https://172.17.0.1
add name=nonetpass key=NONETPASS_ROUTER_USER value=nonetpass
add name=nonetpass key=NONETPASS_ROUTER_PASSWORD value=CHANGE_ME
add name=nonetpass key=NONETPASS_ROUTER_VERIFY_TLS value=false

/container add file=usb1/nonetpass.tar interface=veth-nonetpass envlist=nonetpass \
    root-dir=usb1/nonetpass start-on-boot=yes logging=yes
/container start [find interface=veth-nonetpass]
```

Образ собирается из `Dockerfile` в корне репозитория:
`docker buildx build --platform linux/arm64 -t nonetpass . && docker save nonetpass > nonetpass.tar`.

Если NoNetPass стоит на отдельной машине в сети роутера, пропустите этот шаг
и подставьте её адрес в `--portal` на шаге 8.

## Шаг 8: правила NoNetPass

Сгенерируйте файл под свою сеть (по умолчанию значения из инструкции
провайдера) и импортируйте его:

```sh
nonetpass router-config mikrotik --hotspot-server hotspot1 \
    --hotspot-net 192.168.110.0/24 --portal 172.17.0.2:8080 > nonetpass.rsc
```

```
/import nonetpass.rsc
```

Готовый файл с этими значениями: [`nonetpass.rsc`](nonetpass.rsc). Он
создаёт:

1. списки узлов каждого шлюза `nonetpass-targets-<шлюз>`;
2. правила `walled-garden ip` с окнами для клиентов до входа;
3. доступ к порталу NoNetPass до входа и имя `nonetpass.lan`;
4. правила `forward` для клиентов после входа (нужны, только если эти сервисы
   у вас закрыты в forward, поставьте их выше запрещающих);
5. исключение из masquerade Hotspot для трафика к порталу, чтобы NoNetPass
   видел настоящий IP устройства;
6. пользователя `nonetpass` и REST через `www-ssl` только с адреса NoNetPass.

## Шаг 9: портал для гостей

Портал открывается по адресу `http://nonetpass.lan:8080/`. Страница входа
провайдера (`login.html`) остаётся его, поэтому ссылку на NoNetPass удобно
дать рядом: на табличке с QR-кодом, в имени сети или в приветствии на
портале провайдера, если он это позволяет.

## Проверка

```
/ip hotspot walled-garden ip print where comment~"nonetpass"
/ip firewall address-list print where list~"nonetpass-clients"
```

Во время открытого окна во втором списке появляется IP устройства с
`timeout`, после закрытия он исчезает.

> Синтаксис взят по документации RouterOS 7 и инструкции провайдера. На
> реальном роутере эту связку ещё нужно проверить, в первую очередь поля
> `src-address-list` и `dst-address-list` в `walled-garden ip`.
