"""Автонастройка Keenetic через RCI: от заводского роутера до работающего NoNetPass.

Нужны только адрес роутера, пароль администратора и RADIUS NAS ID. Мастер:

1. входит в RCI под администратором;
2. ставит компонент Captive portal, если команд ``chilli`` ещё нет
   (``components install`` + ``components commit``; роутер обновляется и
   перезагружается, мастер ждёт его);
3. закрепляет за компьютером с NoNetPass его текущий IP (``ip dhcp host``,
   MAC берётся из ARP-таблицы роутера);
4. читает running-config и выполняет те же команды, что генератор конфига
   (гостевая сеть, Captive portal ClientPulse, доступ гостей к порталу,
   пользователь ``nonetpass`` для RCI), затем ``system configuration save``;
5. возвращает настройки NoNetPass для этого роутера.

Ход работы виден по ``steps``: админ-панель показывает его по мере выполнения.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

from .drivers.base import DriverError
from .drivers.keenetic import KeeneticDriver
from .gates import GateCatalog
from .keenetic_config import ConfigError, KeeneticSetup, cli_commands, nonetpass_env_vars

CAPTIVE_COMPONENT = re.compile(r"chilli|captive", re.I)
ALREADY = re.compile(r"duplicate|already", re.I)
CAPTIVE_NAMES = ("chilli", "captive-portal", "captive_portal")


class SetupError(RuntimeError):
    """Шаг не удался; текст объясняет, что сделать."""


@dataclass
class Step:
    title: str
    state: str = "wait"  # wait | run | ok | fail
    detail: str = ""

    def to_dict(self) -> dict:
        return {"title": self.title, "state": self.state, "detail": self.detail}


def _lines(obj) -> list[str]:
    """Строки конфига из ответа RCI (show running-config отдаёт их списком)."""
    if isinstance(obj, list) and all(isinstance(x, str) for x in obj):
        return obj
    if isinstance(obj, dict):
        for key in ("message", "config", "lines"):
            if key in obj:
                return _lines(obj[key])
        for value in obj.values():
            found = _lines(value)
            if found:
                return found
    if isinstance(obj, list):
        for value in obj:
            found = _lines(value)
            if found:
                return found
    return []


def _component_names(obj) -> list[str]:
    """Имена компонентов из ответа ``components list`` (формат зависит от версии KeeneticOS)."""
    names: list[str] = []
    if isinstance(obj, dict):
        comp = obj.get("component")
        if isinstance(comp, dict) and "name" not in comp:
            names += [k for k, v in comp.items() if isinstance(v, dict)]
        if isinstance(obj.get("name"), str):
            names.append(obj["name"])
        for value in obj.values():
            names += _component_names(value)
    elif isinstance(obj, list):
        for value in obj:
            names += _component_names(value)
    return list(dict.fromkeys(names))


@dataclass
class AutoSetup:
    router_url: str
    admin_user: str
    admin_password: str
    setup: KeeneticSetup
    catalog: GateCatalog
    transport: object = None
    reboot_timeout: float = 900
    poll_interval: float = 10
    sleep: object = asyncio.sleep
    steps: list[Step] = field(default_factory=list)
    done: bool = False
    error: str = ""
    env: dict[str, str] = field(default_factory=dict)
    _installed: set[str] = field(default_factory=set)
    admin_fallback: bool = False

    def __post_init__(self):
        self.steps = [Step(t) for t in (
            "Вход в роутер",
            "Компонент Captive portal",
            "Постоянный IP компьютера",
            "Гостевая сеть, Captive portal, доступ к порталу",
            "Сохранение настроек роутера",
        )]

    def to_dict(self) -> dict:
        return {"steps": [s.to_dict() for s in self.steps], "done": self.done, "error": self.error}

    def _driver(self) -> KeeneticDriver:
        return KeeneticDriver(self.router_url, self.admin_user, self.admin_password, acl="",
                              verify_tls=False, state_file=None, transport=self.transport)

    async def _step(self, n: int, coro, ok: str = "") -> object:
        step = self.steps[n]
        step.state = "run"
        try:
            result = await coro
        except (DriverError, ConfigError, SetupError) as exc:
            step.state, step.detail = "fail", str(exc)
            raise
        step.state = "ok"
        step.detail = ok if isinstance(ok, str) else ok(result)
        return result

    async def run(self) -> dict[str, str]:
        driver = None
        try:
            self.setup.validate()
            driver = self._driver()
            await self._step(0, self._login(driver), lambda version: version)
            driver = await self._step(1, self._captive(driver), "есть")
            await self._step(2, self._reserve_ip(driver), lambda mac: f"{self.setup.portal} → {mac}")
            await self._step(3, self._apply(driver), lambda detail: detail or "готово")
            await self._step(4, driver.parse(["system configuration save"]), "сохранено")
        except (DriverError, ConfigError, SetupError) as exc:
            self.error = str(exc)
            raise
        finally:
            self.done = True
            if driver:
                await driver.aclose()
        self.env = nonetpass_env_vars(self.setup, self.router_url)
        if self.admin_fallback:
            self.env.update({"NONETPASS_ROUTER_USER": self.admin_user, "NONETPASS_ROUTER_PASSWORD": self.admin_password})
        return self.env

    async def _login(self, driver: KeeneticDriver) -> str:
        info = await driver.check()
        if not info.get("ok"):
            raise SetupError(f"роутер {self.router_url} не отвечает или неверный пароль: "
                             f"{info.get('error') or info.get('status')}")
        return f"{info.get('model') or 'Keenetic'}, KeeneticOS {info.get('version') or '?'}"

    async def _captive(self, driver: KeeneticDriver) -> KeeneticDriver:
        try:
            await driver.parse(["interface Chilli0"])
            return driver
        except DriverError:
            pass
        names = await self._list_components(driver)
        name = next((n for n in names if CAPTIVE_COMPONENT.search(n)), None)
        if not name and names:
            raise SetupError("не нашёл компонент Captive portal: установите его вручную в «Общих настройках» "
                             "→ «Изменить набор компонентов» и запустите мастер снова "
                             f"(компоненты роутера: {', '.join(names[:40])})")
        if not name:
            # Список компонентов не прочитался: пробуем известные имена.
            name = await self._try_install(driver)
            if not name:
                raise SetupError("не удалось поставить компонент Captive portal автоматически: установите его "
                                 "вручную в «Общих настройках» → «Изменить набор компонентов» и запустите "
                                 "мастер снова")
        self.steps[1].detail = f"ставлю «{name}», роутер обновится и перезагрузится (до 15 минут)"
        if name not in self._installed:
            await driver.parse([f"components install {name}"])
        await driver.parse(["components commit"])
        await driver.aclose()
        driver = await self._wait_back()
        try:
            await driver.parse(["interface Chilli0"])
        except DriverError as exc:
            raise SetupError(f"после установки компонента «{name}» Captive portal не появился ({exc}). Откройте "
                             "«Общие настройки» → «Изменить набор компонентов», поставьте «Captive portal» "
                             "(«Портал авторизации») вручную и запустите мастер снова") from exc
        return driver

    async def _list_components(self, driver: KeeneticDriver) -> list[str]:
        """``components list`` — разные KeeneticOS отдают его по-разному, пробуем все пути."""
        attempts = (
            lambda: driver.parse(["components list"]),
            lambda: driver.show("components/list", {}),
            lambda: driver.show("components/list"),
        )
        for attempt in attempts:
            try:
                names = [n for n in _component_names(await attempt()) if n != "components list"]
            except DriverError:
                continue
            if names:
                return names
        return []

    async def _try_install(self, driver: KeeneticDriver) -> str | None:
        for name in CAPTIVE_NAMES:
            try:
                await driver.parse([f"components install {name}"])
            except DriverError:
                continue
            self._installed.add(name)
            return name
        return None

    async def _wait_back(self) -> KeeneticDriver:
        deadline = time.monotonic() + self.reboot_timeout
        await self.sleep(self.poll_interval * 3)  # роутер ещё не ушёл в перезагрузку
        while time.monotonic() < deadline:
            driver = self._driver()
            if (await driver.check()).get("ok"):
                return driver
            await driver.aclose()
            await self.sleep(self.poll_interval)
        raise SetupError("роутер не вернулся после установки компонента; проверьте его и запустите мастер снова")

    async def _reserve_ip(self, driver: KeeneticDriver) -> str:
        mac = await driver.lookup_mac(self.setup.portal)
        if not mac:
            raise SetupError(f"роутер не видит компьютер {self.setup.portal} в своей сети: проверьте, что "
                             "компьютер подключён к этому роутеру")
        await driver.parse([f"ip dhcp host nonetpass {mac} {self.setup.portal}"])
        return mac

    async def _apply(self, driver: KeeneticDriver) -> str:
        base = "\n".join(_lines(await driver.show("show/running-config"))) or None
        commands = [c for c in cli_commands(self.setup, self.catalog, base).splitlines()
                    if c and not c.startswith("#") and c != "system configuration save"]
        for cmd in commands:
            if cmd.startswith("user nonetpass"):
                continue
            try:
                await driver.parse([cmd])
            except DriverError as exc:
                # Повторный запуск: правило или настройка уже есть — это не ошибка.
                if not ALREADY.search(str(exc)):
                    raise
        if self.setup.mode == "server":
            return await self._ensure_user(driver)
        return ""

    async def _ensure_user(self, driver: KeeneticDriver) -> str:
        """Пользователь ``nonetpass`` для RCI; не вышло — NoNetPass ходит под администратором.

        Синтаксис ``user`` разный в разных KeeneticOS (на 5.1 одной строкой не принимается),
        поэтому пробуем несколько форм и проверяем входом под новым пользователем."""
        pw = self.setup.rci_password
        attempts = (
            lambda: driver.parse(["user nonetpass", f"user nonetpass password {pw}", "user nonetpass tag http"]),
            lambda: driver.show("user", {"name": "nonetpass", "password": pw, "tag": "http"}),
            lambda: driver.show("user", {"nonetpass": {"password": pw, "tag": {"http": True}}}),
        )
        for attempt in attempts:
            try:
                await attempt()
            except DriverError:
                continue
            probe = KeeneticDriver(self.router_url, "nonetpass", pw, acl="", verify_tls=False,
                                   state_file=None, transport=self.transport)
            try:
                if (await probe.check()).get("ok"):
                    return "готово"
            finally:
                await probe.aclose()
        for cmd in ("no user nonetpass",):
            try:
                await driver.parse([cmd])
            except DriverError:
                pass
        self.admin_fallback = True
        return f"готово; NoNetPass будет входить в роутер под «{self.admin_user}»"
