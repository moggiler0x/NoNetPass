#!/bin/sh
# Установка NoNetPass одной командой.
#
#   git clone -b ClientPulse https://github.com/moggiler0x/NoNetPass.git && cd NoNetPass && sudo ./install.sh
#
# Режимы:
#   ./install.sh            Docker, если он есть, иначе Python + systemd
#   ./install.sh --docker   docker compose up -d --build
#   ./install.sh --native   /opt/nonetpass/.venv + служба systemd nonetpass
#
# Настройки берутся из /etc/nonetpass.env (Docker: .env в каталоге проекта).
# Если файла нет, он создаётся из deploy/nonetpass.env.example, а PIN панели и
# ключ cookie генерируются. Существующий файл не перезаписывается.
set -eu

MODE=auto
case "${1:-}" in
  --docker) MODE=docker ;;
  --native) MODE=native ;;
  -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  "") ;;
  *) echo "неизвестный параметр: $1" >&2; exit 2 ;;
esac

SRC=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$SRC/pyproject.toml" ]; then
  echo "запустите install.sh из каталога репозитория NoNetPass" >&2
  exit 1
fi

if [ "$MODE" = auto ]; then
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then MODE=docker; else MODE=native; fi
fi

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

random_digits() { tr -dc '0-9' </dev/urandom | head -c "$1"; }
random_hex() { tr -dc 'a-f0-9' </dev/urandom | head -c "$1"; }

# Создать файл настроек из примера с PIN и ключом, если его ещё нет.
make_env() {
  target=$1
  if [ -f "$target" ]; then
    say "настройки уже есть: $target (не трогаю)"
    return
  fi
  PIN=$(random_digits 6)
  SECRET=$(random_hex 48)
  sed -e "s/^NONETPASS_ADMIN_PIN=$/NONETPASS_ADMIN_PIN=$PIN/" \
      -e "s/^NONETPASS_SECRET=$/NONETPASS_SECRET=$SECRET/" \
      -e "s/^NONETPASS_DRIVER=mikrotik$/NONETPASS_DRIVER=${NONETPASS_DRIVER:-mock}/" \
      "$SRC/deploy/nonetpass.env.example" > "$target"
  chmod 600 "$target"
  say "создан $target, PIN админ-панели: $PIN"
  NEW_ENV=1
}

NEW_ENV=0
if [ "$MODE" = docker ]; then
  make_env "$SRC/.env"
  say "сборка и запуск в Docker"
  (cd "$SRC" && docker compose up -d --build nonetpass)
  ENV_FILE="$SRC/.env"
  RESTART="cd $SRC && docker compose up -d"
else
  if [ "$(id -u)" -ne 0 ]; then
    echo "для установки службы нужен root: sudo ./install.sh --native" >&2
    exit 1
  fi
  command -v python3 >/dev/null 2>&1 || { echo "нужен python3 (3.10+)" >&2; exit 1; }
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "нужен Python 3.10+" >&2; exit 1; }
  id nonetpass >/dev/null 2>&1 || useradd --system --home-dir /var/lib/nonetpass --shell /usr/sbin/nologin nonetpass
  say "Python-окружение в /opt/nonetpass/.venv"
  mkdir -p /opt/nonetpass
  python3 -m venv /opt/nonetpass/.venv
  /opt/nonetpass/.venv/bin/pip install --quiet --upgrade pip
  /opt/nonetpass/.venv/bin/pip install --quiet "$SRC"
  make_env /etc/nonetpass.env
  chgrp nonetpass /etc/nonetpass.env && chmod 640 /etc/nonetpass.env
  install -m 644 "$SRC/deploy/systemd/nonetpass.service" /etc/systemd/system/nonetpass.service
  systemctl daemon-reload
  systemctl enable --now nonetpass
  systemctl restart nonetpass
  ENV_FILE=/etc/nonetpass.env
  RESTART="systemctl restart nonetpass"
fi

ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
ADDR=${ADDR:-127.0.0.1}
say "готово"
echo "  портал:        http://$ADDR:8080/"
echo "  админ-панель:  http://$ADDR:8080/admin"
echo "  метрики:       http://$ADDR:8080/metrics"
echo "  настройки:     $ENV_FILE"
if [ "$NEW_ENV" = 1 ]; then
  echo
  echo "Дальше: впишите в $ENV_FILE драйвер и доступ к роутеру,"
  echo "токен Telegram-бота и chat_id администратора, затем: $RESTART"
fi
