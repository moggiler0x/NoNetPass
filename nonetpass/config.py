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


@dataclass
class Settings:
    # Длительность окна по типу шлюза, секунды.
    verify_window_seconds: float = DEFAULT_VERIFY_WINDOW
    pay_window_seconds: float = DEFAULT_PAY_WINDOW
    # Сколько живёт обнаруженная, но не открытая сессия.
    detect_ttl_seconds: float = 600
    # Минимальная пауза между окнами для одного IP.
    cooldown_seconds: float = 15
    # Максимум открытий окна для одного IP за час.
    max_opens_per_hour: int = 6

    # Переопределение каталога шлюзов (JSON-файл).
    gates_file: str | None = None

    # Драйвер роутера и его параметры.
    driver: str = "mock"
    router_url: str | None = None
    router_user: str | None = None
    router_password: str | None = None
    router_verify_tls: bool = True
    # Имя списка адресов / набора, куда добавляется IP клиента.
    client_list: str = "nonetpass-clients"
    # Доп. параметры драйвера (например, семейство и таблица nftables).
    driver_options: dict[str, str] = field(default_factory=dict)

    # Токен для источников детекции (DNS-логи, прокси, агенты).
    detect_token: str | None = None
    # Токен для админского API.
    admin_token: str | None = None
    # Брать IP клиента из X-Forwarded-For (только за доверенным прокси).
    trust_forwarded: bool = False

    # Журнал сессий (JSON Lines).
    log_path: str = "nonetpass-sessions.jsonl"
    # Лог dnsmasq для встроенной детекции (опционально).
    dns_log_path: str | None = None

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
            gates_file=_env("GATES_FILE"),
            driver=(_env("DRIVER", "mock") or "mock").lower(),
            router_url=_env("ROUTER_URL"),
            router_user=_env("ROUTER_USER"),
            router_password=_env("ROUTER_PASSWORD"),
            router_verify_tls=_bool("ROUTER_VERIFY_TLS", True),
            client_list=_env("CLIENT_LIST", "nonetpass-clients") or "nonetpass-clients",
            driver_options=options,
            detect_token=_env("DETECT_TOKEN"),
            admin_token=_env("ADMIN_TOKEN"),
            trust_forwarded=_bool("TRUST_FORWARDED", False),
            log_path=_env("LOG_PATH", "nonetpass-sessions.jsonl") or "nonetpass-sessions.jsonl",
            dns_log_path=_env("DNS_LOG_PATH"),
        )
