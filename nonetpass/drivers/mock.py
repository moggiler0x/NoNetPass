from __future__ import annotations

from .base import DriverError, Grant, RouterDriver, validate_ipv4


class MockDriver(RouterDriver):
    """Драйвер в памяти для тестов и разработки без роутера."""

    name = "mock"
    can_reboot = True

    def __init__(self, fail_grant: bool = False, fail_revoke: int = 0, macs: dict[str, str] | None = None):
        self.active: dict[str, Grant] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_grant = fail_grant
        self.fail_revoke = fail_revoke
        self.fail_check = False
        self.macs = macs or {}
        self.reboots = 0

    async def grant(self, grant: Grant) -> str:
        validate_ipv4(grant.client_ip)
        if self.fail_grant:
            raise DriverError("mock: grant failed")
        self.calls.append(("grant", grant.client_ip))
        self.active[grant.client_ip] = grant
        return grant.client_ip

    async def revoke(self, client_ip: str, handle: str) -> None:
        if self.fail_revoke:
            self.fail_revoke -= 1
            raise DriverError("mock: revoke failed")
        self.calls.append(("revoke", client_ip))
        self.active.pop(client_ip, None)

    async def check(self) -> dict:
        if self.fail_check:
            raise DriverError("mock: router unreachable")
        return {"ok": True, "model": "mock"}

    async def lookup_mac(self, client_ip: str) -> str | None:
        return self.macs.get(client_ip)

    async def reboot(self) -> None:
        self.calls.append(("reboot", ""))
        self.reboots += 1
