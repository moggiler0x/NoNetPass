"""Проверка узлов шлюзов с машины NoNetPass.

Для каждого узла каталога: резолвится ли имя и открывается ли TCP-порт
443. Это показывает ошибки в каталоге (узел переехал, имя не резолвится)
и проблемы DNS. В закрытом контуре сама машина NoNetPass может не видеть
узлы из-за файрвола; тогда «DNS ok, порт закрыт» — ожидаемый результат.
"""

from __future__ import annotations

import asyncio
import socket
import time

from .gates import GateCatalog


async def check_host(host: str, port: int = 443, timeout: float = 3) -> dict:
    loop = asyncio.get_running_loop()
    result = {"host": host, "dns": False, "addresses": [], "tcp": False, "ms": None, "error": None}
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout)
    except (socket.gaierror, asyncio.TimeoutError, OSError) as exc:
        result["error"] = f"DNS: {exc or 'таймаут'}"
        return result
    addresses = sorted({info[4][0] for info in infos})
    result.update(dns=True, addresses=addresses[:4])
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), timeout)
        writer.close()
        result.update(tcp=True, ms=round((time.monotonic() - started) * 1000))
    except (OSError, asyncio.TimeoutError) as exc:
        result["error"] = f"TCP {port}: {exc or 'таймаут'}"
    return result


async def check_catalog(catalog: GateCatalog, checker=check_host, limit: int = 16) -> list[dict]:
    sem = asyncio.Semaphore(limit)

    async def one(host: str) -> dict:
        async with sem:
            return await checker(host)

    hosts = sorted({h for g in catalog.all for h in g.targets})
    results = dict(zip(hosts, await asyncio.gather(*(one(h) for h in hosts))))
    out = []
    for gate in catalog.all:
        rows = [results[h] for h in gate.targets]
        out.append({
            "gate": gate.id, "name": gate.name, "kind": gate.kind,
            "ok": all(r["dns"] for r in rows), "reachable": sum(r["tcp"] for r in rows),
            "hosts": rows,
        })
    return out


def hosts_text(report: list[dict]) -> str:
    lines = ["🔎 <b>Узлы шлюзов</b> (проверка с машины NoNetPass)"]
    for gate in report:
        total = len(gate["hosts"])
        icon = "✅" if gate["reachable"] == total else ("⚠️" if gate["ok"] else "🔴")
        lines.append(f"{icon} {gate['name']}: доступно {gate['reachable']} из {total}")
        for row in gate["hosts"]:
            if not row["tcp"]:
                lines.append(f"    · {row['host']}: {row['error']}")
    return "\n".join(lines)
