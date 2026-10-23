from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum


class State(str, Enum):
    DETECTED = "detected"  # клиент обратился к шлюзу, ждём запроса кода/оплаты
    OPEN = "open"  # окно на роутере открыто
    CLOSED = "closed"  # правила откатаны, сессия завершена


class CloseReason(str, Enum):
    CODE_ENTERED = "code_entered"  # код введён / платёж подтверждён
    EXPIRED = "expired"
    ABANDONED = "abandoned"  # окно так и не открывали
    REVOKED = "revoked"  # закрыто администратором
    SHUTDOWN = "shutdown"
    RESTART = "restart"  # окно осталось с прошлого запуска и закрыто при старте
    ERROR = "error"


@dataclass
class Session:
    client_ip: str
    source: str
    gate_id: str
    gate_name: str
    kind: str  # verify | pay
    host: str | None = None
    mac: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: State = State.DETECTED
    created_at: float = field(default_factory=time.time)
    opened_at: float | None = None
    expires_at: float | None = None
    closed_at: float | None = None
    close_reason: CloseReason | None = None
    handle: str | None = None
    error: str | None = None
    extends: int = 0
    window: float | None = None

    @property
    def active(self) -> bool:
        return self.state != State.CLOSED

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        data["close_reason"] = self.close_reason.value if self.close_reason else None
        data.pop("handle")
        if self.state == State.OPEN and self.expires_at:
            data["remaining"] = max(0.0, round(self.expires_at - time.time(), 1))
        return data
