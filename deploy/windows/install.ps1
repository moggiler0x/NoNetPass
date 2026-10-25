# Установка NoNetPass на Windows-компьютер рядом с роутером.
#
# Запуск: install.cmd (сам попросит права администратора) или
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Что делает:
#   1. ставит Python 3.12, если его нет (winget или установщик с python.org);
#   2. создаёт C:\ProgramData\NoNetPass\venv и ставит туда NoNetPass с GitHub;
#   3. создаёт nonetpass.env с PIN админ-панели (существующий не трогает);
#   4. регистрирует задачу «NoNetPass» в планировщике: запуск при включении
#      компьютера от имени SYSTEM, перезапуск при падении;
#   5. открывает порт портала в брандмауэре и отключает сон при питании от сети;
#   6. открывает админ-панель, вкладку «Keenetic».
#
# Повторный запуск обновляет NoNetPass до свежей версии из GitHub.

param(
    [string]$Source = "https://github.com/moggiler0x/NoNetPass/archive/refs/heads/ClientPulse.zip",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Root = Join-Path $env:ProgramData "NoNetPass"
$Venv = Join-Path $Root "venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$EnvFile = Join-Path $Root "nonetpass.env"
$Runner = Join-Path $Root "run.cmd"
$Task = "NoNetPass"

function Say($text) { Write-Host "==> $text" -ForegroundColor Cyan }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Запустите установку от имени администратора (install.cmd сделает это сам)." }

New-Item -ItemType Directory -Force -Path $Root | Out-Null

# --- 1. Python ---------------------------------------------------------------
function Find-Python {
    foreach ($cmd in @("py", "python")) {
        $exe = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $pyArgs = if ($cmd -eq "py") { @("-3", "-c") } else { @("-c") }
        $out = & $exe.Source @pyArgs "import sys; print(sys.executable if sys.version_info >= (3, 10) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $out -and (Test-Path $out)) { return $out.Trim() }
    }
    $known = Join-Path $env:ProgramFiles "Python312\python.exe"
    if (Test-Path $known) { return $known }
    return $null
}

$BasePython = Find-Python
if (-not $BasePython) {
    Say "Ставлю Python 3.12"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & $winget.Source install -e --id Python.Python.3.12 --scope machine --silent `
            --accept-package-agreements --accept-source-agreements | Out-Host
    }
    $BasePython = Find-Python
    if (-not $BasePython) {
        $installer = Join-Path $env:TEMP "python-3.12-amd64.exe"
        Invoke-WebRequest "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" -OutFile $installer -UseBasicParsing
        Start-Process $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait
        $BasePython = Find-Python
    }
    if (-not $BasePython) { throw "Не удалось поставить Python. Поставьте Python 3.12 с python.org и запустите установку снова." }
}
Say "Python: $BasePython"

# --- 2. NoNetPass ------------------------------------------------------------
Say "Останавливаю NoNetPass, если он запущен"
Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
Get-Process python, pythonw -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($Venv, [StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force

if (-not (Test-Path $Python)) {
    Say "Создаю окружение $Venv"
    & $BasePython -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "python -m venv завершился с ошибкой" }
}
Say "Ставлю NoNetPass из GitHub"
& $Python -m pip install --quiet --upgrade pip
& $Python -m pip install --quiet --upgrade --force-reinstall $Source
if ($LASTEXITCODE -ne 0) { throw "pip install завершился с ошибкой" }

# --- 3. Настройки ------------------------------------------------------------
$pin = $null
if (-not (Test-Path $EnvFile)) {
    $pin = -join ((1..6) | ForEach-Object { Get-Random -Minimum 0 -Maximum 10 })
    $secret = -join ((1..32) | ForEach-Object { "{0:x}" -f (Get-Random -Minimum 0 -Maximum 16) })
    $data = $Root -replace "\\", "/"
    @(
        "# Настройки NoNetPass. Настройки роутера запишет вкладка «Keenetic» в админ-панели.",
        "NONETPASS_DRIVER=mock",
        "NONETPASS_ADMIN_PIN=$pin",
        "NONETPASS_SECRET=$secret",
        "NONETPASS_LOG_PATH=$data/nonetpass-sessions.jsonl",
        "NONETPASS_STATE_PATH=$data/nonetpass-state.json",
        "NONETPASS_DRIVER_OPT_STATE_FILE=$data/keenetic-state.json",
        "NONETPASS_HOST_REBOOT_CMD=shutdown /r /t 5"
    ) | Set-Content -Path $EnvFile -Encoding UTF8
    # Файл с PIN и паролями: только администраторы и SYSTEM.
    icacls $EnvFile /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
}

# Перезапуск в цикле: после падения или перезапуска из админ-панели служба поднимается сама.
@(
    "@echo off",
    "cd /d `"%~dp0`"",
    "set PYTHONUTF8=1",
    ":loop",
    "`"%~dp0venv\Scripts\python.exe`" -m nonetpass --port $Port --env-file `"%~dp0nonetpass.env`" >> `"%~dp0nonetpass.log`" 2>&1",
    "ping -n 6 127.0.0.1 >nul",
    "goto loop"
) | Set-Content -Path $Runner -Encoding ASCII

# --- 4. Автозапуск -----------------------------------------------------------
Say "Регистрирую автозапуск"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Runner`"" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $Task

# --- 5. Брандмауэр и питание -------------------------------------------------
Say "Открываю порт $Port в брандмауэре"
Get-NetFirewallRule -DisplayName "NoNetPass" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "NoNetPass" -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Allow -Profile Any | Out-Null
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null

# --- 6. Готово ---------------------------------------------------------------
$ip = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
    Select-Object -First 1).IPv4Address.IPAddress
$url = "http://localhost:$Port/admin#keenetic"
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-WebRequest "http://localhost:$Port/healthz" -UseBasicParsing -TimeoutSec 2 | Out-Null; break }
    catch { Start-Sleep -Seconds 2 }
}

Write-Host ""
Write-Host "NoNetPass установлен и запускается вместе с компьютером." -ForegroundColor Green
if ($ip) { Write-Host "Адрес этого компьютера в сети: $ip (закрепите его за компьютером в роутере)" }
Write-Host "Админ-панель: $url"
if ($pin) { Write-Host "PIN админ-панели: $pin" -ForegroundColor Yellow }
else { Write-Host "PIN админ-панели прежний: NONETPASS_ADMIN_PIN в $EnvFile" }
Write-Host "Журнал: $(Join-Path $Root 'nonetpass.log')"
Start-Process $url
