"""Всё, из чего собран запущенный NoNetPass: общее для портала, панели и бота."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import tzinfo

from .blocklist import Blocklist
from .config import Settings
from .control import RouterSet, SystemControl
from .gates import GateCatalog
from .health import HealthMonitor
from .journal import SessionJournal
from .metrics import Metrics
from .sessions import SessionManager
from .store import StateStore


@dataclass
class Context:
    settings: Settings
    catalog: GateCatalog
    manager: SessionManager
    journal: SessionJournal
    store: StateStore
    blocklist: Blocklist
    routers: RouterSet
    control: SystemControl
    health: HealthMonitor
    metrics: Metrics
    tz: tzinfo
    bot: object | None = None

    def apply_overrides(self) -> None:
        """Длительность окон и лимиты, сохранённые из админ-панели."""
        o = self.store.overrides
        if "verify_window" in o:
            self.catalog.set_window("verify", o["verify_window"])
        if "pay_window" in o:
            self.catalog.set_window("pay", o["pay_window"])
        for key in ("cooldown_seconds", "max_opens_per_hour", "extend_seconds", "max_extends"):
            if key in o:
                setattr(self.settings, key, type(getattr(self.settings, key))(o[key]))

    def runtime_settings(self) -> dict:
        s = self.settings
        return {
            "verify_window": self.catalog.window("verify"),
            "pay_window": self.catalog.window("pay"),
            "cooldown_seconds": s.cooldown_seconds,
            "max_opens_per_hour": s.max_opens_per_hour,
            "extend_seconds": s.extend_seconds,
            "max_extends": s.max_extends,
        }
