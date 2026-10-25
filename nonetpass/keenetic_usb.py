"""Флешка, с которой Keenetic сам ставит NoNetPass.

KeeneticOS умеет это штатно: команда ``opkg disk <метка>:/`` монтирует
раздел в /opt, распаковывает в /opt все архивы из папки ``install`` и
запускает initrc, а тот — скрипты /opt/etc/init.d. Генератор кладёт в
``install``:

* установщик Entware для роутера (``aarch64-installer.tar.gz``);
* ``nonetpass.tgz``: настройки NoNetPass, автозапуск ``S99nonetpass`` и
  скрипт первого запуска ``S98nonetpass-setup``, который ставит Python из
  Entware и NoNetPass из GitHub, после чего запускает портал.

Нужны компоненты «Поддержка открытых пакетов» (OPKG) и «Файловая система
Ext», флешка в ext4 с меткой ``NONETPASS`` и интернет на первом запуске.
NoNetPass на самом роутере тянут модели на ARM (aarch64); на MIPS-моделях
pydantic-core не ставится, для них режим server.
"""

from __future__ import annotations

import io
import secrets
import tarfile
import urllib.request

from .keenetic_config import KeeneticSetup, nonetpass_env

SOURCE = "https://github.com/moggiler0x/NoNetPass/archive/refs/heads/ClientPulse.tar.gz"
ENTWARE_INSTALLER = "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz"
INSTALLER_NAME = "aarch64-installer.tar.gz"
PACKAGE_NAME = "nonetpass.tgz"

# Совпадает с deploy/keenetic/S99nonetpass (проверяется тестом).
INIT_SCRIPT = """\
#!/bin/sh
# /opt/etc/init.d/S99nonetpass — NoNetPass на Keenetic (Entware).

ENABLED=yes
PROCS=python3
ARGS="-m nonetpass --port 8080"
PREARGS=""
DESC="NoNetPass"
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin

export NONETPASS_DRIVER=ipset
export NONETPASS_LOG_PATH=/opt/var/log/nonetpass-sessions.jsonl
# Настройки из генератора (nonetpass keenetic-config) перекрывают значения выше.
if [ -f /opt/etc/nonetpass.env ]; then set -a; . /opt/etc/nonetpass.env; set +a; fi

. /opt/etc/init.d/rc.func
"""


def setup_script(source: str = SOURCE) -> str:
    return f"""\
#!/bin/sh
# /opt/etc/init.d/S98nonetpass-setup — первый запуск NoNetPass на Keenetic.
# Ставит Python из Entware и NoNetPass из GitHub, затем запускает портал.
# Если не вышло (нет интернета), повторит при следующей загрузке роутера.
# Журнал: /opt/var/log/nonetpass-install.log

PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
SOURCE="{source}"
DONE=/opt/var/nonetpass/installed
LOG=/opt/var/log/nonetpass-install.log

[ "$1" = start ] || exit 0
[ -f "$DONE" ] && exit 0
mkdir -p /opt/var/nonetpass /opt/var/log

(
  set -e
  echo "=== $(date) установка NoNetPass"
  n=0
  until opkg update; do
    n=$((n + 1)); [ "$n" -ge 20 ] && exit 1
    sleep 30
  done
  opkg install python3 python3-pip
  pip3 install --no-cache-dir "$SOURCE"
  touch "$DONE"
  echo "=== $(date) готово"
  /opt/etc/init.d/S99nonetpass start
) >>"$LOG" 2>&1 &
"""


def router_env(setup: KeeneticSetup, pin: str, secret: str) -> str:
    return nonetpass_env(setup) + (
        "NONETPASS_DRIVER_OPT_STATE_FILE=/opt/var/nonetpass/keenetic-state.json\n"
        "NONETPASS_STATE_PATH=/opt/var/nonetpass/state.json\n"
        "NONETPASS_LOG_PATH=/opt/var/log/nonetpass-sessions.jsonl\n"
        f"NONETPASS_ADMIN_PIN={pin}\n"
        f"NONETPASS_SECRET={secret}\n"
    )


def new_pin() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def package(setup: KeeneticSetup, pin: str, secret: str, source: str = SOURCE) -> bytes:
    """nonetpass.tgz: распаковывается роутером в /opt."""
    files = [
        ("opt/etc/nonetpass.env", router_env(setup, pin, secret), 0o600),
        ("opt/etc/init.d/S98nonetpass-setup", setup_script(source), 0o755),
        ("opt/etc/init.d/S99nonetpass", INIT_SCRIPT, 0o755),
    ]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, content, mode in files:
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def download_installer(url: str = ENTWARE_INSTALLER, timeout: float = 30) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        data = resp.read()
    if data[:2] != b"\x1f\x8b":
        raise OSError("ответ не похож на архив .tar.gz")
    return data
