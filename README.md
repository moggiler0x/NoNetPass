# AuthPass (2FA-Gatekeeper)

Сервис-компаньон для закрытых сетей без сотовой связи. Когда пользователь
входит через разрешённый SSO-шлюз (`id.vk.com`) и платформа присылает код
подтверждения в заблокированный мессенджер, AuthPass открывает на роутере
короткое окно (по умолчанию 60 с) **только для IP этого устройства** и
**только к узлам доставки кода** (`im.vk.com`, `api.vk.com`), а затем
откатывает правило.

## Как это работает

1. **Детекция.** Обращение клиента к шлюзу фиксируется по логу DNS
   (dnsmasq, встроено), вебхуком от прокси/DNS (`POST /api/detect`) или самим
   пользователем в панели.
2. **Панель.** Локальная страница `http://<authpass>:8080/` по WebSocket
   показывает статус шлюза, таймер, доступность узлов доставки и кнопку
   «Получить код». Панель действует только для IP того, кто её открыл.
3. **JIT-окно.** Драйвер роутера добавляет IP клиента в список
   `authpass-clients`. Разовое правило на роутере разрешает трафик из этого
   списка к узлам доставки. Где роутер это умеет, запись создаётся с
   таймаутом, поэтому окно закроется даже при падении AuthPass.
4. **Auto-Revoke.** Кнопка «Я ввёл код» или истечение таймера удаляют
   запись (с повторами при сбое связи с роутером). При остановке сервиса все
   окна закрываются.
5. **Журнал.** Каждое изменение состояния пишется в JSON Lines
   (`AUTHPASS_LOG_PATH`), доступно через `/api/admin/journal`.

Защита от злоупотреблений: одно окно на IP, пауза между окнами
(`AUTHPASS_COOLDOWN_SECONDS`), лимит открытий в час
(`AUTHPASS_MAX_OPENS_PER_HOUR`), строгая проверка IPv4 перед любой командой
роутеру.

## Роутеры

AuthPass работает в двух режимах: **на самом роутере** или **на отдельной
машине** (Raspberry Pi, сервер, контейнер), управляя роутером по API.

| Роутер | На роутере | С отдельной машины | Таймаут на роутере |
|---|---|---|---|
| MikroTik RouterOS 7 | контейнер (`deploy/mikrotik/container.md`) | `mikrotik` (REST) | да |
| MikroTik RouterOS 6 | — | `mikrotik-api` (API 8728/8729) | да |
| Keenetic | Entware, `ipset` (`deploy/keenetic`) | `keenetic` (RCI) | `ipset`: да, RCI: нет* |
| OpenWrt 22.03+ | `nftables` (`deploy/openwrt`) | `openwrt` (ubus) | да |
| ASUS Merlin, DD-WRT, OpenWrt fw3, любой Linux с iptables | `ipset` | — | да |
| OPNsense | — | `opnsense` (API, алиас) | нет* |

\* Без таймаута на роутере окно закрывает только AuthPass (с повторами);
у Keenetic RCI правила не сохраняются в startup-config и чистятся при
следующем старте AuthPass.

Готовые конфиги для разовой настройки роутера лежат в `deploy/`.

## Запуск

```sh
pip install .
cp deploy/authpass.env.example .env   # заполните драйвер и доступ к роутеру
set -a; . ./.env; set +a
authpass --port 8080
```

Или в Docker: `docker build -t authpass . && docker run --env-file .env -p 8080:8080 authpass`.

Без роутера: `AUTHPASS_DRIVER=mock authpass` — окна открываются «в памяти».

### Настройки

| Переменная | По умолчанию | |
|---|---|---|
| `AUTHPASS_DRIVER` | `mock` | драйвер роутера |
| `AUTHPASS_ROUTER_URL`, `_USER`, `_PASSWORD` | | доступ к роутеру (для OPNsense: API key/secret) |
| `AUTHPASS_ROUTER_VERIFY_TLS` | `true` | проверять сертификат роутера |
| `AUTHPASS_CLIENT_LIST` | `authpass-clients` | список/набор клиентов (в nft/ipset `-` → `_`) |
| `AUTHPASS_WINDOW_SECONDS` | `60` | длительность окна |
| `AUTHPASS_GATEWAY_HOSTS` | `id.vk.com` | узлы SSO, запускающие сессию |
| `AUTHPASS_TARGET_HOSTS` | `im.vk.com,api.vk.com` | узлы доставки кода |
| `AUTHPASS_COOLDOWN_SECONDS` / `_MAX_OPENS_PER_HOUR` | `15` / `6` | лимиты |
| `AUTHPASS_DETECT_TOKEN` / `AUTHPASS_ADMIN_TOKEN` | | Bearer-токены |
| `AUTHPASS_DNS_LOG_PATH` | | лог dnsmasq для детекции |
| `AUTHPASS_TRUST_FORWARDED` | `false` | брать IP из `X-Forwarded-For` |
| `AUTHPASS_DRIVER_OPT_*` | | опции драйвера: `FAMILY`, `TABLE`, `TARGETS_SET`, `ACL`, `GRANT_CMD`, `REVOKE_CMD`, `STATE_FILE` |

> Если код приходит push-уведомлением в мобильное приложение, а не в веб-чат,
> добавьте в `AUTHPASS_TARGET_HOSTS` узлы push-сервиса платформы
> (например, `mtalk.google.com` для Android).

## API

| Метод | Путь | Доступ |
|---|---|---|
| GET | `/` | панель пользователя |
| WS | `/ws` | события сессии для IP клиента |
| GET | `/api/me` | состояние для IP клиента |
| POST | `/api/me/open` | открыть окно для своего IP |
| POST | `/api/me/done` | код введён, закрыть окно |
| POST | `/api/detect` | детекция `{client_ip, host, source}`, токен детекции |
| GET | `/api/admin/sessions`, `/api/admin/journal` | админ |
| POST | `/api/admin/sessions/{id}/revoke` | админ |
| WS | `/ws/admin?token=…` | все события |
| GET | `/healthz` | статус и связь с роутером |

## Разработка

```sh
pip install -e '.[dev]'
pytest
```

Дальше по плану: Headless Relay (код забирает сервер через изолированный
шлюз и показывает в панели, не открывая доступ устройству).
