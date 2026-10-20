"""Настройки AuthPass. Всё читается из переменных окружения с префиксом AUTHPASS_."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"AUTHPASS_{name}", default)


def _list(name: str, default: str) -> tuple[str, ...]:
    raw = _env(name, default) or ""
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def _bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # Длительность окна доступа к узлам доставки, секунды.
    window_seconds: float = 60
    # Сколько живёт обнаруженная, но не открытая сессия.
    detect_ttl_seconds: float = 600
    # Минимальная пауза между окнами для одного IP.
    cooldown_seconds: float = 15
    # Максимум открытий окна для одного IP за час.
    max_opens_per_hour: int = 6

    # Узлы SSO-шлюза: обращение к ним означает начало верификации.
    gateway_hosts: tuple[str, ...] = ("id.vk.com",)
    # Узлы доставки кода, которые открываются на время окна.
    target_hosts: tuple[str, ...] = ("im.vk.com", "api.vk.com")

    # Драйвер роутера и его параметры.
    driver: str = "mock"
    router_url: str | None = None
    router_user: str | None = None
    router_password: str | None = None
    router_verify_tls: bool = True
    # Имя списка адресов / набора, куда добавляется IP клиента.
    client_list: str = "authpass-clients"
    # Доп. параметры драйвера (например, семейство и таблица nftables).
    driver_options: dict[str, str] = field(default_factory=dict)

    # Токен для источников детекции (DNS-логи, прокси, агенты).
    detect_token: str | None = None
    # Токен для админского API.
    admin_token: str | None = None
    # Брать IP клиента из X-Forwarded-For (только за доверенным прокси).
    trust_forwarded: bool = False

    # Журнал сессий (JSON Lines).
    log_path: str = "authpass-sessions.jsonl"
    # Лог dnsmasq для встроенной детекции (опционально).
    dns_log_path: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        options = {
            key[len("AUTHPASS_DRIVER_OPT_"):].lower(): value
            for key, value in os.environ.items()
            if key.startswith("AUTHPASS_DRIVER_OPT_")
        }
        return cls(
            window_seconds=float(_env("WINDOW_SECONDS", "60")),
            detect_ttl_seconds=float(_env("DETECT_TTL_SECONDS", "600")),
            cooldown_seconds=float(_env("COOLDOWN_SECONDS", "15")),
            max_opens_per_hour=int(_env("MAX_OPENS_PER_HOUR", "6")),
            gateway_hosts=_list("GATEWAY_HOSTS", "id.vk.com"),
            target_hosts=_list("TARGET_HOSTS", "im.vk.com,api.vk.com"),
            driver=(_env("DRIVER", "mock") or "mock").lower(),
            router_url=_env("ROUTER_URL"),
            router_user=_env("ROUTER_USER"),
            router_password=_env("ROUTER_PASSWORD"),
            router_verify_tls=_bool("ROUTER_VERIFY_TLS", True),
            client_list=_env("CLIENT_LIST", "authpass-clients") or "authpass-clients",
            driver_options=options,
            detect_token=_env("DETECT_TOKEN"),
            admin_token=_env("ADMIN_TOKEN"),
            trust_forwarded=_bool("TRUST_FORWARDED", False),
            log_path=_env("LOG_PATH", "authpass-sessions.jsonl") or "authpass-sessions.jsonl",
            dns_log_path=_env("DNS_LOG_PATH"),
        )
