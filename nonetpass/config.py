"""Настройки NoNetPass. Всё читается из переменных окружения с префиксом NONETPASS_."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .gates import DEFAULT_PAY_WINDOW, DEFAULT_VERIFY_WINDOW, GateCatalog, load_catalog


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"NONETPASS_{name}", default)


def _bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str) -> list[str]:
    return [item.strip() for item in (_env(name) or "").replace(";", ",").split(",") if item.strip()]


def _ids(name: str) -> list[int]:
    out = []
    for item in _list(name):
        try:
            out.append(int(item))
        except ValueError:
            raise ValueError(f"NONETPASS_{name}: {item!r} не похож на chat_id") from None
    return out


@dataclass
class RouterSpec:
    """Дополнительный роутер: только мониторинг и перезагрузка, окна не открывает."""

    name: str
    driver: str
    url: str | None = None
    user: str | None = None
    password: str | None = None
    verify_tls: bool = True


def _routers() -> list[RouterSpec]:
    specs = []
    for name in _list("ROUTERS"):
        key = name.upper().replace("-", "_")
        driver = (_env(f"ROUTER_{key}_DRIVER") or "").lower()
        if not driver:
            raise ValueError(f"роутер {name}: не задан NONETPASS_ROUTER_{key}_DRIVER")
        specs.append(RouterSpec(
            name=name, driver=driver,
            url=_env(f"ROUTER_{key}_URL"),
            user=_env(f"ROUTER_{key}_USER"),
            password=_env(f"ROUTER_{key}_PASSWORD"),
            verify_tls=_bool(f"ROUTER_{key}_VERIFY_TLS", True),
        ))
    return specs


@dataclass
class Settings:
    # Длительность окна по типу шлюза, секунды.
    verify_window_seconds: float = DEFAULT_VERIFY_WINDOW
    pay_window_seconds: float = DEFAULT_PAY_WINDOW
    # Сколько живёт обнаруженная, но не открытая сессия.
    detect_ttl_seconds: float = 600
    # Минимальная пауза между окнами для одного IP.
    cooldown_seconds: float = 15
    # Максимум открытий окна для одного устройства (IP или MAC) за час.
    max_opens_per_hour: int = 6
    # «Продлить»: на сколько секунд и сколько раз за окно.
    extend_seconds: float = 60
    max_extends: int = 1
    # Чёрный список из окружения (дополняется из админ-панели и бота).
    blocked_macs: list[str] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)

    # Переопределение каталога шлюзов (JSON-файл).
    gates_file: str | None = None

    # Драйвер роутера и его параметры.
    driver: str = "mock"
    router_url: str | None = None
    router_user: str | None = None
    router_password: str | None = None
    router_verify_tls: bool = True
    # Как роутер называется в панели и боте.
    router_name: str = "main"
    # Имя списка адресов / набора, куда добавляется IP клиента.
    client_list: str = "nonetpass-clients"
    # Дополнительные роутеры (мониторинг и перезагрузка).
    routers: list[RouterSpec] = field(default_factory=list)
    # Доп. параметры драйвера (например, семейство и таблица nftables).
    driver_options: dict[str, str] = field(default_factory=dict)

    # Токен для источников детекции (DNS-логи, прокси, агенты).
    detect_token: str | None = None
    # Токен для админского API.
    admin_token: str | None = None
    # Вход в админ-панель: PIN и/или логин с паролем.
    admin_pin: str | None = None
    admin_user: str | None = None
    admin_password: str | None = None
    # Подсети, из которых открыта админ-панель (пусто: любые).
    admin_networks: list[str] = field(default_factory=list)
    # Ключ подписи cookie панели; без него ключ случайный на каждый запуск.
    secret: str | None = None
    login_max_failures: int = 5
    login_lockout_seconds: float = 300
    # Токен для /metrics (пусто: метрики открыты).
    metrics_token: str | None = None

    # Telegram-бот администратора.
    telegram_token: str | None = None
    telegram_admin_ids: list[int] = field(default_factory=list)
    telegram_api: str = "https://api.telegram.org"
    telegram_proxy: str | None = None

    # Мониторинг: период проверок и сколько неудач подряд считать сбоем.
    health_interval_seconds: float = 30
    health_fail_after: int = 2

    # Отчёты: часовой пояс, день и час ежемесячного отчёта.
    timezone: str = "Europe/Moscow"
    report_day: int = 1
    report_hour: int = 9

    # Перезапуск NoNetPass и перезагрузка сервера из панели и бота.
    allow_restart: bool = True
    host_reboot_cmd: str | None = None
    reboot_cooldown_seconds: float = 300
    # Брать IP клиента из X-Forwarded-For (только за доверенным прокси).
    trust_forwarded: bool = False

    # Журнал сессий (JSON Lines).
    log_path: str = "nonetpass-sessions.jsonl"
    # Лог dnsmasq для встроенной детекции (опционально).
    dns_log_path: str | None = None
    # UDP-порт для syslog роутера (DNS-запросы MikroTik, dnsmasq OpenWrt/Keenetic).
    syslog_port: int | None = None
    syslog_host: str = "0.0.0.0"
    # С каких адресов принимать syslog (пусто: с любых).
    syslog_allow: list[str] = field(default_factory=list)
    # Состояние между запусками: открытые окна, чёрный список, настройки панели.
    state_path: str = "nonetpass-state.json"

    def catalog(self) -> GateCatalog:
        return load_catalog(self.verify_window_seconds, self.pay_window_seconds, self.gates_file)

    @classmethod
    def from_env(cls) -> "Settings":
        options = {
            key[len("NONETPASS_DRIVER_OPT_"):].lower(): value
            for key, value in os.environ.items()
            if key.startswith("NONETPASS_DRIVER_OPT_")
        }
        return cls(
            verify_window_seconds=float(_env("VERIFY_WINDOW_SECONDS", str(DEFAULT_VERIFY_WINDOW))),
            pay_window_seconds=float(_env("PAY_WINDOW_SECONDS", str(DEFAULT_PAY_WINDOW))),
            detect_ttl_seconds=float(_env("DETECT_TTL_SECONDS", "600")),
            cooldown_seconds=float(_env("COOLDOWN_SECONDS", "15")),
            max_opens_per_hour=int(_env("MAX_OPENS_PER_HOUR", "6")),
            extend_seconds=float(_env("EXTEND_SECONDS", "60")),
            max_extends=int(_env("MAX_EXTENDS", "1")),
            blocked_macs=_list("BLOCKED_MACS"),
            blocked_ips=_list("BLOCKED_IPS"),
            gates_file=_env("GATES_FILE"),
            driver=(_env("DRIVER", "mock") or "mock").lower(),
            router_url=_env("ROUTER_URL"),
            router_user=_env("ROUTER_USER"),
            router_password=_env("ROUTER_PASSWORD"),
            router_verify_tls=_bool("ROUTER_VERIFY_TLS", True),
            router_name=_env("ROUTER_NAME", "main") or "main",
            client_list=_env("CLIENT_LIST", "nonetpass-clients") or "nonetpass-clients",
            routers=_routers(),
            driver_options=options,
            detect_token=_env("DETECT_TOKEN"),
            admin_token=_env("ADMIN_TOKEN"),
            admin_pin=_env("ADMIN_PIN"),
            admin_user=_env("ADMIN_USER"),
            admin_password=_env("ADMIN_PASSWORD"),
            admin_networks=_list("ADMIN_NETWORKS"),
            secret=_env("SECRET"),
            login_max_failures=int(_env("LOGIN_MAX_FAILURES", "5")),
            login_lockout_seconds=float(_env("LOGIN_LOCKOUT_SECONDS", "300")),
            metrics_token=_env("METRICS_TOKEN"),
            telegram_token=_env("TELEGRAM_TOKEN"),
            telegram_admin_ids=_ids("TELEGRAM_ADMIN_IDS"),
            telegram_api=_env("TELEGRAM_API", "https://api.telegram.org") or "https://api.telegram.org",
            telegram_proxy=_env("TELEGRAM_PROXY"),
            health_interval_seconds=float(_env("HEALTH_INTERVAL_SECONDS", "30")),
            health_fail_after=int(_env("HEALTH_FAIL_AFTER", "2")),
            timezone=_env("TIMEZONE", "Europe/Moscow") or "Europe/Moscow",
            report_day=int(_env("REPORT_DAY", "1")),
            report_hour=int(_env("REPORT_HOUR", "9")),
            allow_restart=_bool("ALLOW_RESTART", True),
            host_reboot_cmd=_env("HOST_REBOOT_CMD"),
            reboot_cooldown_seconds=float(_env("REBOOT_COOLDOWN_SECONDS", "300")),
            trust_forwarded=_bool("TRUST_FORWARDED", False),
            log_path=_env("LOG_PATH", "nonetpass-sessions.jsonl") or "nonetpass-sessions.jsonl",
            dns_log_path=_env("DNS_LOG_PATH"),
            syslog_port=int(_env("SYSLOG_PORT")) if _env("SYSLOG_PORT") else None,
            syslog_host=_env("SYSLOG_HOST", "0.0.0.0") or "0.0.0.0",
            syslog_allow=_list("SYSLOG_ALLOW"),
            state_path=_env("STATE_PATH", "nonetpass-state.json") or "nonetpass-state.json",
        )
