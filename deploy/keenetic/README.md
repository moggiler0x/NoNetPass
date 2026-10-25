# Keenetic

## Вариант А: NoNetPass на роутере через Entware (рекомендуется)

Нужны: USB-накопитель или встроенный Entware (KeeneticOS 4.x), компоненты
«Пакеты OPKG» и «Модули ядра подсистемы Netfilter». Модели на aarch64
(Giga KN-1011, Ultra KN-1811, Hopper, Peak и т.п.) тянут Python + FastAPI;
на MIPS-моделях используйте вариант Б.

```sh
opkg update && opkg install python3 python3-pip ipset iptables
pip3 install nonetpass-*.whl
cp 50-nonetpass.sh /opt/etc/ndm/netfilter.d/ && chmod +x /opt/etc/ndm/netfilter.d/50-nonetpass.sh
cp S99nonetpass /opt/etc/init.d/ && chmod +x /opt/etc/init.d/S99nonetpass
/opt/etc/init.d/S99nonetpass start
```

Хук `netfilter.d` вызывается прошивкой при каждой пересборке правил, поэтому
правило-окно не пропадёт. NoNetPass работает с драйвером `ipset`: резолвит
узлы выбранного шлюза и кладёт в набор `nonetpass_pairs` пары «IP клиента,IP
узла» с таймаутом, поэтому окно открывает только узлы этого шлюза. Хук
генерируется командой `nonetpass router-config ipset`.

## Вариант Б: NoNetPass на отдельной машине, роутер по RCI

Драйвер `keenetic` открывает окно правилами `access-list` через RCI
(`NONETPASS_ROUTER_URL=http://192.168.1.1`, пользователь с правом доступа к
веб-интерфейсу). Изменения не сохраняются в startup-config, поэтому
перезагрузка тоже закрывает окно. Список доступа `nonetpass` нужно один раз
создать и привязать к сегменту в CLI так, чтобы permit-правила NoNetPass
стояли перед запрещающими. Синтаксис CLI отличается между версиями
KeeneticOS; при необходимости шаблоны команд меняются через
`NONETPASS_DRIVER_OPT_GRANT_CMD` и `NONETPASS_DRIVER_OPT_REVOKE_CMD`
(подстановки `{acl}`, `{src}`, `{dst}`).

## Генератор конфига: Captive portal ClientPulse + NoNetPass

Повторяет инструкцию ClientPulse «Настройка авторизации на Keenetic WiFly»
(гостевая сеть, Captive portal с профилем Clientpulse, RADIUS NAS ID зоны)
и сразу добавляет настройки NoNetPass. Первым спрашивает NAS ID:

```sh
nonetpass keenetic-config                 # вопросы по очереди
nonetpass keenetic-config --nas-id Sv12345 --base startup-config.txt --ssid "Free WiFi"
```

То же есть в админ-панели, вкладка «Keenetic»: заполнить поля, приложить
startup-config, скачать архив.

В архиве:

* `startup-config.txt` — текущий конфиг роутера с изменениями. Загружается в
  «Управление» → «Параметры системы» → «Файлы» → startup-config → «Заменить
  файл». Файл целиком заменяет настройки роутера, поэтому собирается только из
  конфига этого же роутера (скачать там же): интернет, пароль администратора и
  остальное остаются как были. Без исходного конфига готового файла не будет;
* `keenetic-commands.txt` — те же изменения командами CLI для командной строки
  веб-интерфейса (`my.keenetic.net/webcli`), конфиг для них не нужен;
* `usb/` — содержимое флешки, с которой роутер сам ставит NoNetPass (режим
  router), или `nonetpass.env` для NoNetPass на отдельной машине (режим server);
* `README.txt` — порядок действий.

Что меняется в конфиге:

* гостевые точки доступа 2,4 и 5 ГГц: имя сети, пароль или открытая сеть,
  включены;
* `interface Chilli0`: `chilli profile Clientpulse`, `chilli radiusnasid <NAS ID>`,
  `chilli dhcpif` гостевого моста, `chilli uamallowed` адреса NoNetPass и
  `chilli uamdomain` страниц входа шлюзов (id.vk.ru, id.sber.ru, ...). Если
  Captive portal уже настроен, остальные его параметры сохраняются;
* `ip nat Chilli0` и `ip host nonetpass.lan <адрес NoNetPass>`;
* в режиме «отдельная машина» — пользователь `nonetpass` с тегом `http` для RCI.

Окна NoNetPass открывает через RCI командой `interface Chilli0 chilli
uamallowed <IP узла>` и закрывает `no chilli uamallowed`, без сохранения в
startup-config. Captive portal пропускает uamallowed для всех гостей, а не для
одного устройства, поэтому на время окна узлы доставки выбранного шлюза
открыты всей гостевой сети. Если два устройства одновременно открыли один и
тот же шлюз, закрытие первого окна закрывает эти узлы и для второго.

### NoNetPass ставится сам с флешки (режим router)

KeeneticOS умеет ставить пакеты с флешки без консоли: команда `opkg disk
NONETPASS:/` (её добавляет генератор) монтирует раздел в `/opt`, распаковывает
архивы из папки `install` и запускает скрипты `/opt/etc/init.d`. Генератор
кладёт в `usb/install`:

* `aarch64-installer.tar.gz` — установщик Entware (скачивается с
  bin.entware.net при генерации; если не скачался, README.txt скажет, что
  положить);
* `nonetpass.tgz` — `nonetpass.env` с PIN админ-панели, автозапуск
  `S99nonetpass` и `S98nonetpass-setup`. При первом запуске он ставит
  `python3`, `python3-pip` и NoNetPass с GitHub (ветка ClientPulse), затем
  запускает портал. Журнал: `/opt/var/log/nonetpass-install.log`; без
  интернета установка повторится при следующей загрузке.

Нужны компоненты «Поддержка открытых пакетов» и «Файловая система Ext» и
флешка ext4 с меткой `NONETPASS`. Если Entware на роутере уже стоит (в
startup-config есть `opkg disk`), генератор его не трогает: достаточно
положить `nonetpass.tgz` в папку `install` этого диска.

Подходят только модели с USB на ARM (aarch64): Giga KN-1011/1012, Ultra,
Peak, Hopper и т.п. На Air, Lite, Start и других MIPS-моделях без USB
NoNetPass на роутере не запустится: для них режим server, например
[Windows-компьютер в той же сети](../windows/README.md). В этом режиме генератор
добавляет пользователя `nonetpass` для RCI и список доступа `_NONETPASS_PORTAL`,
который пускает гостей к порталу на компьютере в домашней сети.

Компонент «Captive portal» конфигом не ставится: сначала обновите KeeneticOS
и установите компонент в «Общих настройках», как в шагах 2-4 инструкции
ClientPulse. Команды взяты из справочника CLI KeeneticOS 4.x; на живом
роутере генератор пока не проверялся.
