"""Метрики в формате Prometheus для Grafana (``GET /metrics``).

Счётчики копятся с момента запуска; Prometheus сам считает ``increase()``
за нужный период. Готовый дашборд: ``deploy/grafana/nonetpass.json``.
"""

from __future__ import annotations

import time
from collections import Counter

from .health import LEVEL
from .models import Session

PREFIX = "nonetpass"


def _labels(**labels: str) -> str:
    if not labels:
        return ""
    body = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
    return "{" + body + "}"


def _escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    def __init__(self, manager, health, blocklist, version: str):
        self.manager = manager
        self.health = health
        self.blocklist = blocklist
        self.version = version
        self.started = time.time()
        self.events: Counter[tuple[str, str, str]] = Counter()
        self.closes: Counter[tuple[str, str]] = Counter()
        self.window_seconds_sum = 0.0
        self.window_count = 0
        self.refused: Counter[str] = Counter()
        manager.listeners.append(self.on_event)

    def on_event(self, event: str, session: Session, extra: dict) -> None:
        self.events[(event, session.gate_id, session.kind)] += 1
        if event == "closed":
            self.closes[(extra.get("reason") or "unknown", session.kind)] += 1
            if session.opened_at and session.closed_at:
                self.window_seconds_sum += session.closed_at - session.opened_at
                self.window_count += 1

    def refuse(self, reason: str) -> None:
        self.refused[reason] += 1

    def render(self) -> str:
        out: list[str] = []

        def metric(name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
            out.append(f"# HELP {PREFIX}_{name} {help_text}")
            out.append(f"# TYPE {PREFIX}_{name} {kind}")
            for labels, value in samples:
                out.append(f"{PREFIX}_{name}{_labels(**labels)} {value:g}")

        metric("info", "gauge", "Версия и драйвер", [({"version": self.version, "driver": self.manager.driver.name}, 1)])
        metric("uptime_seconds", "gauge", "Время работы", [({}, round(time.time() - self.started))])
        metric("session_events_total", "counter", "События сессий по шлюзам",
               [({"event": e, "gate": g, "kind": k}, v) for (e, g, k), v in sorted(self.events.items())])
        metric("windows_closed_total", "counter", "Закрытые сессии по причинам",
               [({"reason": r, "kind": k}, v) for (r, k), v in sorted(self.closes.items())])
        metric("window_open_seconds_sum", "counter", "Суммарная длительность открытых окон",
               [({}, round(self.window_seconds_sum, 1))])
        metric("window_open_seconds_count", "counter", "Число закрытых окон", [({}, self.window_count)])
        metric("open_refused_total", "counter", "Отказы в открытии окна",
               [({"reason": r}, v) for r, v in sorted(self.refused.items())])
        active = Counter(s.kind for s in self.manager.active_windows())
        metric("windows_active", "gauge", "Открытые окна сейчас",
               [({"kind": k}, active.get(k, 0)) for k in ("verify", "pay")])
        metric("blocklist_entries", "gauge", "Записей в чёрном списке", [({}, len(self.blocklist))])
        checks = list(self.health.checks.values())
        metric("health_status", "gauge", "Статус проверки: 0 ok, 1 предупреждение, 2 сбой",
               [({"check": c.id}, LEVEL[c.status]) for c in checks])
        routers = [c for c in checks if c.id.startswith("router:")]
        metric("router_up", "gauge", "Роутер отвечает",
               [({"router": c.id[7:]}, 1 if c.status == "ok" else 0) for c in routers])
        metric("router_latency_ms", "gauge", "Время ответа роутера",
               [({"router": c.id[7:]}, c.info.get("latency_ms", 0)) for c in routers])
        return "\n".join(out) + "\n"
