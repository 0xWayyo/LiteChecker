# LiteChecker

Версия 0.6.3 использует отдельные подписанные каналы обновлений для macOS,
Windows и Linux и очищает старые управляемые версии. Без настроенного канала
статус обновлений — `unconfigured`. Инструкции пользователю —
[обновления](updates.md), выпуск релизов — [инструкция владельца](../development/releases.md).

LiteChecker проверяет доступность каждого VLESS/REALITY-выхода и SNI-доменов из нескольких сетей. При обычной установке каждый компьютер самостоятельно обновляет подписку и отправляет отчёты в настроенный Telegram-чат; на Windows уведомления необязательны. Устройство получает постоянный уникальный ID; город и имя устройства задаются отдельно, в одном городе может быть много устройств.

## Быстрый запуск и перенос

Пошаговая инструкция: [установка агента](../installation/agent.md). Скачайте клиентский ZIP для своей ОС: [macOS](../../MACOS.md), [Windows](../../WINDOWS.md) или [Linux](../../LINUX.md). Распакуйте его в новую папку и откройте `INSTALL.command` (macOS), `LiteChecker.bat` (Windows) или `bash INSTALL.sh` (Linux). В macOS и Windows рядом с файлом запуска находятся `_app` и инструкция; сохраняйте их вместе. Настройки вводятся на устройстве, ввод виден в терминале. macOS и Windows используют native DIRECT; Linux требует Docker Engine и Compose и проверяет через маршрут Docker/хоста.

С версии 0.6.0 обновляйтесь через меню с сохранением настроек и ID. Для перехода с тестовых версий 0.2–0.5 нужна отдельная установка; перед запуском новой остановите старую. Автоматического переноса тестовых данных и сброса старого канала нет.

### macOS: постоянный DIRECT

Установщик размещает программу в `~/Library/Application Support/LiteChecker`, готовит закреплённые uv/Python/Xray и запускает пользовательскую службу `com.litechecker.direct`. Первый цикл начинается сразу, следующие — с интервалом 600 секунд по монотонным часам, без параллельных циклов и очереди пропущенных запусков после сна. Служба запускается при входе пользователя в macOS и перезапускается после аварийного завершения. Проверок во сне или при выключенном компьютере нет.

Каждый цикл заново определяет физический интерфейс и его DHCP DNS, обновляет подписку и проводит DNS/TCP/TLS/VLESS-проверки через привязанные к этому интерфейсу соединения. При ошибке прямого маршрута нет переключения на системный VPN. Город и сеть в DIRECT-отчёте относятся к выходу проверок, а не к обычному выходу компьютера. Привязка к интерфейсу не гарантирует обход VPN на роутере или системных фильтров; Kill Switch может сделать проверки невозможными.

Во время macOS-проверки параметры подключения сверяются перед началом, периодически
с паузой 2 секунды и перед сохранением результата. Проверка снимка ограничена
10 секундами. Смена интерфейса, индекса, IP-адресов или DHCP DNS (даже при прежнем
имени `en0`) отменяет текущую попытку с ожиданием завершения её запросов/Xray/relay.
Если параметры не удалось прочитать, результаты также не считаются достоверными,
но подтверждённая смена сети не заявляется. После паузы 2 секунды выполняется
не более одной новой попытки: новое определение сети, контроль выхода, свежая
подписка и новые проверки. Обе попытки делят общий лимит `run_deadline_seconds + 30`;
внешний лимит службы `run_deadline_seconds + 60` сохранён. Доставка через прежнюю
Telegram-очередь получает только итог: свежий отчёт с короткой пометкой о повторе
либо одно сообщение о невозможности завершить проверку без списка серверов.

Это сравнение локальных параметров, не универсальный детектор смены провайдера:
смена сети с полностью совпавшими параметрами или очень короткий переход между
опросами может остаться незамеченным. Настройки маршрутизации, DNS и VPN не меняются.
В Windows сохранена отдельная существующая проверка интерфейса; этот macOS-монитор
на Windows/Linux не включается.

`state/native-direct/last-observation.json` содержит последний завершённый отчёт
без конфигураций подписки. При обнаруженном прерывании он заменяется записью с
`report: null`, временем и причиной, чтобы предыдущий успех не выглядел текущим.
Файл `last-probe-attempts.json` также заменяется пустым списком попыток с причиной
прерывания: результаты отменённого прогона не остаются последней диагностикой.
Следующая завершённая проверка заменяет эту запись. Другие ранние ошибки до начала
измерений и ручная остановка до первого результата могут не создать этот файл.
Для диагностики присылайте его либо `status.json` и `service.log`, но не
`snapshot.json` и не папку `secrets`.

Для управления повторно откройте `INSTALL.command`. Установщик очищает только проверенные файлы внутри `_app` и оставляет переход к постоянной программе; не отделяйте файл запуска от `_app`. Дополнительные команды из постоянной папки программы: `bash run.sh status`, `bash run.sh stop`, `bash run.sh start`, `bash run.sh logs`. Обновления через меню сохраняют настройки, секреты и ID устройства. Чужую рабочую папку переносить на другое устройство нельзя.

Служба сохраняет результаты и состояние доставки в `state/native-direct` внутри постоянной папки. Telegram-очередь переживает перезапуск; успешная проверка и подтверждённая доставка — разные состояния. Сообщения прошлых циклов получают пометку «Отложенная доставка» и сохраняют исходное время наблюдения: это не новая проверка старых адресов. Лимит очереди — 32 сообщения / 256 ожидающих частей; при переполнении удаляются старые сообщения целиком, счётчик пропусков и `outbox-overflow` видны в `status.json`. После сбоя в момент подтверждения отдельная часть сообщения может повториться.

### Windows: native DIRECT

Откройте `LiteChecker.bat`, пройдите мастер и запустите проверки первым пунктом меню. WSL, Docker и права администратора не нужны. Проверки начинаются сразу после запуска и повторяются каждые 10 минут. Закрытие меню не останавливает мониторинг. Выбор «Запустить» / «Остановить» сохраняется: после входа в Windows возобновляется только ранее включённый мониторинг. После обновления со старой версии один раз откройте меню и запустите проверки для настройки автозагрузки. Настройки, отчёты и диагностика находятся в `_app/windows-state`.

DIRECT использует физический интерфейс и Cloudflare DoH. При недоступности выбранного подключения измерение не переключается на обычный маршрут. Универсальный обход VPN и Kill Switch не гарантируется. Диагностика сети доступна через меню настроек; для поддержки используйте `last-report.txt` или `last-diagnostics.txt`.

### Linux: standalone в Docker

После настройки через `bash INSTALL.sh` для ручного управления из постоянной папки доступны:

```bash
bash run.sh status
bash run.sh stop
bash run.sh check  # только при остановленном фоновом экземпляре
bash run.sh start
```

Подпись устройства и город определяются автоматически и могут быть переопределены вручную. Не копируйте состояние первого компьютера на остальные. Проверки начинаются сразу, следующие — через 600 секунд после окончания цикла. Подписка загружается заново в каждом цикле. Доставка в Telegram имеет дисковую очередь и повторы; `check` не считает один лишь приём в локальную очередь успешной отправкой. Docker использует маршрут хоста; при стороннем VPN он может измерять выход VPN.

Дополнительно сохранён централизованный режим `agent` + `collector` для тех, кому нужен внешний контроль пропавших устройств. Только в этом режиме используются разные агентские токены, реестр и публичный HTTPS-адрес collector. Для обычной установки по инструкции выше они **не нужны**. Разделы о collector ниже относятся к этому дополнительному режиму.

## Telegram через отдельный прокси

Если Telegram недоступен напрямую, задайте прокси через меню настроек. При ручной настройке macOS/Linux сохраните адрес в `secrets/telegram_proxy_url` с правами `0600`. Формат: `socks5://LOGIN:PASSWORD@IP:PORT` (поддерживаются также `socks5h://`, `http://` и `https://`). Спецсимволы в логине/пароле должны быть URL-encoded. В Windows используйте мастер: он сохраняет настройки в `_app/windows-state`.

В постоянной macOS-установке секрет лежит в `~/Library/Application Support/LiteChecker/secrets/telegram_proxy_url` и определяется автоматически; существующий файл сохраняется при обновлении. В Docker `bash run.sh start` / `check` подключают отдельный `compose.telegram-proxy.yml`, который монтирует только этот секрет; существующая `.env.standalone` не перезаписывается. После добавления/изменения прокси перезапустите соответствующий режим.

**Через этот прокси идёт только доставка Telegram.** Подписка, IPinfo, DNS/TCP/TLS и VLESS-проверки его не используют. Прокси не меняет измеряемый интернет-выход. Адрес Telegram передаётся SOCKS-прокси для разрешения DNS, HTTPS-сертификат Telegram проверяется. Отключения проверки сертификата нет.

Без настройки прокси сохраняется обычная отправка. Некорректная настройка отклоняется; если сам прокси недоступен, отправка повторяется с ним, **без скрытого перехода напрямую**. Постоянный native DIRECT и обычный standalone сохраняют ограниченную очередь на диске.

Для ручного host-запуска/collector: `LC_TELEGRAM_PROXY_URL_FILE` указывает на секрет; файл имеет приоритет над `LC_TELEGRAM_PROXY_URL`. В контейнере collector дополнительно смонтируйте этот файл read-only. Не задавайте глобальный `ALL_PROXY` / `HTTPS_PROXY` ради Telegram. Библиотека `requests` не нужна: уже используется [поддержка прокси HTTPX](https://www.python-httpx.org/advanced/proxies/).

Передавайте публичный клиентский ZIP; подписку, данные бота и прокси вводите отдельно на каждом устройстве. Сборка исключает секреты и локальное состояние устройств.

## Что означает результат

Для VPN `UP/E2E` появляется только после успешного ответа хотя бы одного из двух контрольных HTTPS-сайтов через конкретный VLESS/REALITY outbound в Xray. Каждому сайту выделяется часть общего таймаута, чтобы зависание первого не мешало проверить второй. DNS, TCP и запрос вида `http://IP:443` не подтверждают работоспособность VPN.

В текущих исходниках TCP ожидается до 8 секунд на IP, VPN/E2E и отдельный TLS — до 30 секунд. Для VPN это общий бюджет на два контрольных сайта, не 30 секунд каждому. Native DNS на Windows/macOS ограничен 6 секундами на запрос A или AAAA; Linux использует системный resolver в рамках дедлайна цикла. Явные `LC_TCP_TIMEOUT_SECONDS` / `LC_PROBE_TIMEOUT_SECONDS` имеют приоритет над новыми значениями по умолчанию.

После первого прохода только результаты `DOWN` проверяются ещё один раз, после паузы 10 секунд. Повтор использует тот же набор конфигураций текущего цикла и те же сетевые зависимости, заново разрешает доменные имена и не переключается на обычный маршрут или Telegram-прокси. Контроль сети проверяется перед повтором и после него, если остались `DOWN`. При сбое контроля такой отказ становится `UNKNOWN`, а не доказательством недоступности сервера. Не хватило времени на повтор/его подтверждение — `UNKNOWN / DEADLINE`; общая граница цикла остаётся 480 секунд, завершение процессов не пересекается со следующим циклом.

Успешный повтор даёт обычный `UP`: ни отдельной строки, ни жёлтого предупреждения в Telegram нет. Если все адреса доступны, отправляется короткий итог. Первый неудачный результат сохраняется только в приватном `last-probe-attempts.json` внутри папки состояния; файл заменяется каждый цикл, не накапливается и не содержит outbound, подписку или Telegram-секреты. Ошибка записи этой диагностики не меняет результат измерения. Новые таймауты и перепроверка доступны начиная с 0.6.1; ранее опубликованные ZIP v0.6.0 остаются неизменными.

Из подписки берутся все указанные IP, полные доменные имена серверов (включая поддомены) и уникальные `realitySettings.serverName`. SNI-домен проверяется отдельно на порту 443: DNS → TCP → TLS с проверкой цепочки сертификата и имени хоста. Соединение идёт к уже проверенному IP, а имя SNI остаётся исходным. Ответ страницы 403/404 не влияет на эту TLS-проверку. Результат хранится с `check_kind=sni`, поэтому не смешивается с VPN.

SNI в соединении с VPN-сервером проверяется самим Xray в составе E2E. Прямой TLS-запрос к сайту SNI — дополнительная независимая проверка: недоступность этого сайта с агента сама по себе не доказывает отказ VPN. [Назначение REALITY и транспортных настроек в документации Xray](https://xtls.github.io/en/config/transport.html).

Для домена проверяются DNS-адреса до первого подтверждённого успеха; доступность имени означает наличие рабочего маршрута, а не исправность каждого IP балансировщика. IP, явно записанные отдельными выходами в подписке, проверяются независимо. Неизвестные поддомены и родительские домены автоматически не придумываются: например, проверка `vpn.example.com` не означает проверку `example.com`.

| Условия | Статус и этап |
| --- | --- |
| Обе прямые HTTPS-canary недоступны | `UNKNOWN / AGENT_NETWORK` |
| DNS-ответ некорректен, запрещён политикой или превышает безопасный предел | `UNKNOWN / POLICY` |
| Прямой контроль работает, домен не резолвится | `DOWN / DNS` |
| Прямой контроль работает, TCP не устанавливается | `DOWN / TCP` |
| Xray отсутствует или глобально не запускается | `UNKNOWN / XRAY` |
| Общий дедлайн исчерпан | `UNKNOWN / DEADLINE` |
| DNS/TCP работают, но обе HTTPS-canary через outbound не прошли | `DOWN / VLESS_E2E` |
| HTTPS-canary через выбранный outbound вернула ожидаемый код | `UP / E2E` |
| TLS к сайту SNI установлен, сертификат и имя проверены | `UP / TLS` (SNI) |
| Сертификат сайта SNI не прошёл проверку | `DOWN / TLS_CERTIFICATE` (SNI) |
| TCP отвечает, TLS к сайту SNI не установлен | `DOWN / TLS_HANDSHAKE` (SNI) |

`UNKNOWN` означает, что агент не получил достаточного доказательства о сервере. Это не то же самое, что подтверждённый `DOWN`.

В Telegram перечисляются только проблемные адреса с понятной причиной. При полном успехе свежего цикла приходит короткое «Всё доступно» с количеством VPN-адресов и SNI. При старой подписке, неполной проверке, задержке доставки или сбое самого агента остаётся предупреждение — такие циклы не получают сообщение о полном успехе. Таймаут — результат конкретной попытки из конкретной сети, а не автоматическое заключение о блокировке. Время успешного TCP не показывается как задержка неработающего VPN.

В DIRECT-отчёте город вынесен в заголовок, устройство, ОС и время UTC — на следующую строку. Интерфейс, IP, ASN и провайдер показаны одной строкой; обычный выход указан отдельно. Полный успех занимает одну строку: `Всё доступно · VPN 44/44 · SNI 20/20`. Причины ошибок сокращены, например `Порт отвечает, VPN: таймаут`; диагностические коды остаются в локальном JSON. Внизу — ID агента и версия, создавшая отчёт: `ID: device-… · v0.6.1` (для старых отчётов без версии — `v?`).

При обновлении сначала обновите collector, затем агентов: новые агенты передают поле `check_kind` и TLS-этапы. SQLite автоматически мигрирует с сохранением истории; предыдущие результаты считаются VPN-проверками. Старые агенты совместимы с обновлённым collector. Если подписку не удалось обновить, новые агенты не проверяют ни VPN, ни SNI из сохранённого списка.

## Безопасная конфигурация

CLI не принимает URL и секреты аргументами: они попали бы в список процессов. Конфигурация читается из переменных `LC_*`, а токен агента, URL подписки, ключ состояния и Telegram-токен — из файлов через `*_FILE`. Файлы с секретами и `agents.json` должны иметь режим `0600`, каталоги — `0700`.

Создайте токен агента строго в формате `lc_` плюс 43 URL-safe символа (256 бит):

```bash
uv sync --all-groups --frozen
install -d -m 700 secrets
umask 077
uv run python -c 'from litechecker.security import generate_agent_token; print(generate_agent_token())' > secrets/agent_token
uv run python -c 'import secrets; print(secrets.token_urlsafe(32))' > secrets/state_key
chmod 600 secrets/agent_token secrets/state_key
```

Сначала `uv sync` устанавливает пакет, поэтому импорт генератора гарантирован. В установленной host-версии используйте полный путь к Python из venv, например `/opt/litechecker/.venv/bin/python`, а не неопределённый `python`.

У каждого агента должен быть свой токен. Скопируйте его один раз через защищённый канал в соответствующую запись `agents.json`; при компрометации удалите или замените только эту запись и перезапустите collector. Не передавайте токен в командной строке и не вставляйте секреты в issue или логи.

## Telegram и реестр агентов

1. Создайте бота командой `/newbot` у BotFather, добавьте его в нужный чат и отправьте в чат тестовое сообщение.
2. На доверенном компьютере запросите `getUpdates` у Telegram Bot API и возьмите `message.chat.id`; для топика дополнительно задайте `LC_TELEGRAM_TOPIC_ID`. Не помещайте bot token в историю shell или аргументы процесса.
3. Сохраните bot token в `secrets/telegram_bot_token` с режимом `0600`.
4. Скопируйте `examples/agents.example.json` в `agents.json`, замените демонстрационный токен на сгенерированный и выполните `chmod 600 agents.json`.

Формат записи:

```json
{
  "<REPLACE_WITH_AGENT_ID>": {
    "token": "REPLACE_WITH_UNIQUE_AGENT_TOKEN",
    "city": "Tbilisi",
    "name": "Home ISP",
    "expected_interval_seconds": 600
  }
}
```

Значения `city` и `name` доверенно задаёт collector; агент не может подменить город в отчёте.

## Первый запуск в Docker

Нужны Docker Engine с Compose и публичные DNS-записи `A`/`AAAA` для collector. Пример включает Caddy: только он публикует `80/443`, автоматически получает и обновляет TLS-сертификат, а collector доступен ему лишь в отдельной internal-сети. Отдельная egress-сеть collector нужна только для Telegram API.

```bash
set -euo pipefail
cp examples/.env.collector.example .env.collector
cp examples/.env.agent.example .env.agent
cp examples/.env.compose.example .env
cp examples/agents.example.json agents.json
install -d -m 700 secrets
install -d -m 700 state state/collector state/tbilisi-agent
install -m 600 /dev/null secrets/telegram_bot_token
install -m 600 /dev/null secrets/subscription_url
chmod 600 .env .env.collector .env.agent agents.json
docker compose -f compose.example.yml build --pull
umask 077
docker run --rm --entrypoint /opt/litechecker/.venv/bin/python litechecker:local \
  -c 'from litechecker.security import generate_agent_token; print(generate_agent_token())' \
  > secrets/agent_token
docker run --rm --entrypoint /opt/litechecker/.venv/bin/python litechecker:local \
  -c 'import secrets; print(secrets.token_urlsafe(32))' \
  > secrets/state_key
"${EDITOR:-vi}" .env .env.collector .env.agent agents.json
"${EDITOR:-vi}" secrets/telegram_bot_token secrets/subscription_url
# В .env задайте CADDY_DOMAIN, CADDY_EMAIL и numeric identity владельца:
# LITECHECKER_UID=$(id -u)
# LITECHECKER_GID=$(id -g)
# Заполните bot token, subscription URL, chat ID, HTTPS collector URL и
# замените невалидный token-placeholder в agents.json содержимым agent_token.
chmod 600 .env .env.collector .env.agent agents.json secrets/*
chmod 700 secrets state state/collector state/tbilisi-agent
```

Compose требует явные `LITECHECKER_UID`/`LITECHECKER_GID` и запускает оба Python-процесса именно от владельца bind-mounted файлов. На Docker Desktop задайте значения `id -u`/`id -g` пользователя macOS; на native Linux — пользователя deployment. Каталоги state также остаются его собственностью. Это одинаково удовлетворяет owner-проверкам registry/`*_FILE` без ослабления режима `0600`.

```bash
docker compose -f compose.example.yml config --quiet
docker compose -f compose.example.yml up -d collector caddy
curl --fail "https://$(sed -n 's/^CADDY_DOMAIN=//p' .env)/healthz"
```

`.dockerignore` работает как allowlist, поэтому созданные до сборки `secrets/`, `agents.json`, `.env*`, state/SQLite, raw subscription/config, `.git`, worktrees и caches не попадают в build context. До замены `.invalid`, UID/GID и token-placeholder пример намеренно не запускается. SQLite и очередь сохраняются в `state/collector`; сертификаты Caddy — в volumes `caddy-data`/`caddy-config`. Root filesystem контейнеров read-only, `/tmp` — `tmpfs`, capabilities сброшены.

После выбранного платформенного шага запустите agent-профиль; все три secret-файла уже созданы и имеют окончательные права:

```bash
docker compose -f compose.example.yml --profile agent run --rm tbilisi-agent agent --once
docker compose -f compose.example.yml --profile agent up -d tbilisi-agent
```

`--once` выполняет ровно один цикл и возвращает `0` только после ACK collector именно для текущего event; оставшийся pending report даёт закрытый exit `1`. Коды выхода CLI: `0` — штатное завершение, `2` — ошибка конфигурации, `1` — фатальная ошибка выполнения. Docker healthcheck вызывает `litechecker agent-health` и требует недавний успешный ACK, а не только свежий snapshot. Telegram не вызывается самим агентом: агент отправляет отчёт только collector.

Безопасная parser-проверка подписки без временного raw-файла, Xray, collector и Telegram читает URL/ключ только из настроенных `*_FILE`, обрабатывает ответ в памяти и печатает лишь count, revision prefix и число IP/domain:

```bash
docker compose -f compose.example.yml --profile agent run --rm \
  --entrypoint /opt/litechecker/.venv/bin/python tbilisi-agent \
  -m litechecker.smoke
```

Полный smoke добавляет direct control и тот же `probe_all`, что использует агент: точный Xray VLESS/REALITY outbound, две штатные HTTPS-canary и общий deadline. Collector, state/outbox и Telegram при этом не вызываются; вывод дополнительно содержит только `FRESH`, status/stage counts:

```bash
docker compose -f compose.example.yml --profile agent run --rm \
  --entrypoint /opt/litechecker/.venv/bin/python tbilisi-agent \
  -m litechecker.smoke --probe
```

SIGINT/SIGTERM отменяют активный smoke и возвращают управление только после cleanup дочернего Xray-процесса. В host-установке эквивалентные команды — `litechecker-smoke-subscription` и `litechecker-smoke-subscription --probe` из установленного venv. Не сохраняйте raw subscription в `/tmp`; если диагностический инструмент всё же создал такой файл, сразу задайте `0600` и удалите его в `finally`.

## Добавление второго города

1. На collector сгенерируйте новый уникальный токен и добавьте новую запись, например `warsaw-vps`, в `agents.json`.
2. Подготовьте user-owned копию и замените registry атомарно в той же файловой системе:

```bash
set -euo pipefail
AGENTS_NEXT="$(mktemp ./agents.json.next.XXXXXX)"
trap 'rm -f "$AGENTS_NEXT"' EXIT
cat agents.json > "$AGENTS_NEXT"
"${EDITOR:-vi}" "$AGENTS_NEXT"
chmod 600 "$AGENTS_NEXT"
mv -f "$AGENTS_NEXT" agents.json
trap - EXIT
```

3. Перезапустите collector, чтобы перечитать реестр.
4. На второй машине загрузите тот же проверенный image. На первой машине создайте immutable artifact и передайте tar, checksum и значение `IMAGE_ID` через доверенный канал:

```bash
set -euo pipefail
EXPECTED_IMAGE_ID_FILE=litechecker-image.id
docker image inspect --format '{{.Id}}' litechecker:local > "$EXPECTED_IMAGE_ID_FILE"
test -s "$EXPECTED_IMAGE_ID_FILE"
docker image save litechecker:local --output litechecker-image.tar
shasum -a 256 litechecker-image.tar > litechecker-image.tar.sha256
```

Передайте `litechecker-image.tar`, `litechecker-image.tar.sha256` и `litechecker-image.id`. На чистом втором host сначала загрузите image, затем прочитайте ожидаемый ID, получите ID фактически загруженного image и выполните архитектурную проверку:

```bash
set -euo pipefail
EXPECTED_IMAGE_ID_FILE=litechecker-image.id
shasum -a 256 -c litechecker-image.tar.sha256
docker image load --input litechecker-image.tar
EXPECTED_IMAGE_ID=$(tr -d '\r\n' < "$EXPECTED_IMAGE_ID_FILE")
LOADED_IMAGE_ID=$(docker image inspect --format '{{.Id}}' litechecker:local)
test -n "$EXPECTED_IMAGE_ID"
test "$LOADED_IMAGE_ID" = "$EXPECTED_IMAGE_ID"
HOST_ARCH=$(uname -m)
IMAGE_ARCH=$(docker image inspect --format '{{.Architecture}}' litechecker:local)
case "$HOST_ARCH:$IMAGE_ARCH" in
  x86_64:amd64|aarch64:arm64|arm64:arm64) ;;
  *) echo "image-architecture-mismatch" >&2; exit 1 ;;
esac
docker run --rm --entrypoint /usr/local/bin/xray litechecker:local version | grep '^Xray 26\.3\.27'
```

Поле `Architecture` проверяется только после `docker image load`; image ID одинаков только для одинакового локально загруженного образа, а не между независимо собранными multi-arch вариантами.

Для запуска только агента передайте также `examples/.env.agent.example`, `examples/.env.compose.example`, `compose.agent.example.yml`, `Dockerfile`, `.dockerignore`, `pyproject.toml`, `uv.lock` и `src/`. На втором host:

```bash
set -euo pipefail
cp examples/.env.agent.example .env.agent
install -d -m 700 secrets state state/agent
install -m 600 /dev/null secrets/agent_token
install -m 600 /dev/null secrets/subscription_url
install -m 600 /dev/null secrets/state_key
chmod 600 .env.agent secrets/*
export LITECHECKER_UID=$(id -u)
export LITECHECKER_GID=$(id -g)
# После checksum/image-ID/Architecture проверки и заполнения placeholders:
docker compose -f compose.agent.example.yml run --rm agent agent --once
docker compose -f compose.agent.example.yml up -d agent
```

Эквивалентный `docker run` обязан передать тот же env-файл, UID/GID, state и все три secret mount:

```bash
docker run --rm --user "$(id -u):$(id -g)" --env-file .env.agent \
  --volume "$PWD/state/agent:/var/lib/litechecker" \
  --volume "$PWD/secrets/agent_token:/run/secrets/agent_token:ro" \
  --volume "$PWD/secrets/subscription_url:/run/secrets/subscription_url:ro" \
  --volume "$PWD/secrets/state_key:/run/secrets/state_key:ro" \
  litechecker:local agent --once
```

Source-build fallback: если image tar недоступен, передайте полный перечисленный build context и выполните `docker compose -f compose.agent.example.yml build --pull`; зафиксируйте checksum checkout и новый image ID. Затем сохраните переданный токен, URL подписки и новый ключ состояния в отдельных файлах `0600`.
5. Задайте новый `LC_AGENT_ID`, выполните `litechecker agent --once`, убедитесь, что отчёт принят, затем включите daemon/service.

Для третьего и следующих городов повторяется только профиль агента: отдельные ID, token, state volume и машина; collector остаётся один.

Все `FROM` в Dockerfile закреплены одновременно читаемым tag и multi-arch manifest digest. При обновлении сначала проверьте новый digest командой `docker buildx imagetools inspect IMAGE:TAG`, внесите ровно показанный manifest digest, затем запустите `scripts/verify-release.sh` и сохраните evidence проверки в release notes.

## Linux: systemd

Ниже приведён bootstrap для свежего Ubuntu 24.04. Перед запуском установите [официальный `uv 0.8.22`](https://github.com/astral-sh/uv/releases/tag/0.8.22) именно как `/usr/local/bin/uv`; первая проверка прекращает установку при другой версии. Команды запускаются из корня checkout с `pyproject.toml`, `uv.lock` и `src/`: зависимости и сам пакет синхронизируются из lock-файла прямо в service venv. Xray `26.3.27` также проверяется по SHA-256 до установки:

```bash
set -euo pipefail
sudo apt-get update
sudo apt-get install --yes ca-certificates curl python3.12 python3.12-venv
test "$(/usr/local/bin/uv --version | awk '{print $1, $2}')" = "uv 0.8.22"
case "$(uname -m)" in
  x86_64)
    XRAY_ASSET=Xray-linux-64.zip
    XRAY_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
    ;;
  aarch64|arm64)
    XRAY_ASSET=Xray-linux-arm64-v8a.zip
    XRAY_SHA256=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c
    ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
XRAY_TMP="$(mktemp -d)"
trap 'rm -rf "$XRAY_TMP"' EXIT
curl --fail --location \
  "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/$XRAY_ASSET" \
  --output "$XRAY_TMP/xray.zip"
if ! printf '%s  %s\n' "$XRAY_SHA256" "$XRAY_TMP/xray.zip" | sha256sum --check -; then
  echo "Xray checksum verification failed" >&2
  exit 1
fi
python3.12 -m zipfile -e "$XRAY_TMP/xray.zip" "$XRAY_TMP/unpacked"
sudo useradd --system --home /var/lib/litechecker --shell /usr/sbin/nologin litechecker
sudo install -d -o root -g root -m 755 /opt/litechecker
sudo install -d -o root -g root -m 755 /opt/litechecker/app
sudo install -o root -g root -m 644 pyproject.toml uv.lock README.md /opt/litechecker/app/
sudo cp -R src /opt/litechecker/app/src
sudo env UV_PROJECT_ENVIRONMENT=/opt/litechecker/.venv \
  UV_PYTHON=/usr/bin/python3.12 \
  /usr/local/bin/uv sync --frozen --no-dev --no-editable \
  --project /opt/litechecker/app
sudo install -o root -g root -m 755 "$XRAY_TMP/unpacked/xray" /usr/local/bin/xray
sudo install -d -o root -g litechecker -m 750 /etc/litechecker
sudo install -d -o litechecker -g litechecker -m 700 /etc/litechecker/secrets
sudo install -d -o litechecker -g litechecker -m 700 /var/lib/litechecker
sudo install -o litechecker -g litechecker -m 600 /dev/null /etc/litechecker/secrets/agent_token
sudo install -o litechecker -g litechecker -m 600 /dev/null /etc/litechecker/secrets/subscription_url
sudo install -o litechecker -g litechecker -m 600 /dev/null /etc/litechecker/secrets/state_key
sudo -u litechecker /opt/litechecker/.venv/bin/python \
  -c 'from litechecker.security import generate_agent_token; print(generate_agent_token())' \
  | sudo -u litechecker tee /etc/litechecker/secrets/agent_token >/dev/null
sudo -u litechecker /opt/litechecker/.venv/bin/python \
  -c 'import secrets; print(secrets.token_urlsafe(32))' \
  | sudo -u litechecker tee /etc/litechecker/secrets/state_key >/dev/null
sudo -u litechecker sh -c 'umask 077; cat > /etc/litechecker/secrets/subscription_url'
# Вставьте HTTPS URL подписки и нажмите Ctrl-D; затем передайте agent token
# администратору collector через защищённый канал.
```

Создайте `/etc/litechecker/agent.env` с режимом `0600`. Он содержит только несекретные настройки и пути к созданным secret-файлам; замените ID и публичный HTTPS URL collector:

```bash
sudo tee /etc/litechecker/agent.env >/dev/null <<'EOF'
LC_AGENT_ID=<REPLACE_WITH_AGENT_ID>
LC_AGENT_TOKEN_FILE=/etc/litechecker/secrets/agent_token
LC_COLLECTOR_URL=https://collector.example.invalid
LC_SUBSCRIPTION_URL_FILE=/etc/litechecker/secrets/subscription_url
LC_STATE_KEY_FILE=/etc/litechecker/secrets/state_key
LC_STATE_DIR=/var/lib/litechecker
LC_XRAY_BINARY=/usr/local/bin/xray
LC_INTERVAL_SECONDS=600
LC_RUN_DEADLINE_SECONDS=480
LC_ALLOW_INSECURE_COLLECTOR=false
EOF
sudo chmod 600 /etc/litechecker/agent.env
sudo chown root:root /etc/litechecker/agent.env
sudoedit /etc/litechecker/agent.env
sudo install -o root -g root -m 644 deploy/litechecker-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now litechecker-agent
sudo systemctl status litechecker-agent
```

Unit запускает `/opt/litechecker/.venv/bin/python -m litechecker.cli agent`, перезапускается после ошибки с задержкой 10 секунд, запрещает повышение привилегий и разрешает запись только в `/var/lib/litechecker`.

## macOS: launchd для дополнительного collector-режима

Команды запускаются из корня checkout с `pyproject.toml`, `uv.lock` и `src/`. Предварительно установите [официальный `uv 0.8.22`](https://github.com/astral-sh/uv/releases/tag/0.8.22); bootstrap проверяет точную версию, а затем синхронизирует lock-файл прямо в venv из plist. Он ставит Homebrew Python 3.12, выбирает официальный Xray `26.3.27` для Intel/Apple Silicon и проверяет SHA-256. Шаблонный `/Users/REPLACE_ME/Library/Application Support/LiteChecker/.venv/bin/python` заменяется на абсолютный путь текущего пользователя. Затем замените ID и публичный HTTPS URL в готовом plist.

```bash
set -euo pipefail
brew install python@3.12
UV_BIN="$(command -v uv)"
test "$("$UV_BIN" --version | awk '{print $1, $2}')" = "uv 0.8.22"
case "$(uname -m)" in
  x86_64)
    XRAY_ASSET=Xray-macos-64.zip
    XRAY_SHA256=f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203
    ;;
  arm64)
    XRAY_ASSET=Xray-macos-arm64-v8a.zip
    XRAY_SHA256=2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf
    ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
XRAY_TMP="$(mktemp -d)"
trap 'rm -rf "$XRAY_TMP"' EXIT
curl --fail --location \
  "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/$XRAY_ASSET" \
  --output "$XRAY_TMP/xray.zip"
if ! printf '%s  %s\n' "$XRAY_SHA256" "$XRAY_TMP/xray.zip" | shasum -a 256 -c -; then
  echo "Xray checksum verification failed" >&2
  exit 1
fi
PYTHON312="$(brew --prefix python@3.12)/bin/python3.12"
"$PYTHON312" -m zipfile -e "$XRAY_TMP/xray.zip" "$XRAY_TMP/unpacked"
LITECHECKER_DIR="$HOME/Library/Application Support/LiteChecker"
install -d -m 700 "$LITECHECKER_DIR"
install -d -m 700 "$LITECHECKER_DIR/secrets" "$LITECHECKER_DIR/state"
install -d -m 755 "$LITECHECKER_DIR/app"
install -m 644 pyproject.toml uv.lock README.md "$LITECHECKER_DIR/app/"
ditto src "$LITECHECKER_DIR/app/src"
UV_PROJECT_ENVIRONMENT="$LITECHECKER_DIR/.venv" UV_PYTHON="$PYTHON312" \
  "$UV_BIN" sync --frozen --no-dev --no-editable \
  --project "$LITECHECKER_DIR/app"
sudo install -d -o root -g wheel -m 755 /usr/local/bin
sudo install -o root -g wheel -m 755 "$XRAY_TMP/unpacked/xray" /usr/local/bin/xray
umask 077
"$LITECHECKER_DIR/.venv/bin/python" \
  -c 'from litechecker.security import generate_agent_token; print(generate_agent_token())' \
  > "$LITECHECKER_DIR/secrets/agent_token"
"$LITECHECKER_DIR/.venv/bin/python" \
  -c 'import secrets; print(secrets.token_urlsafe(32))' \
  > "$LITECHECKER_DIR/secrets/state_key"
cat > "$LITECHECKER_DIR/secrets/subscription_url"
# Вставьте HTTPS URL подписки и нажмите Ctrl-D.
chmod 600 "$LITECHECKER_DIR/secrets/"*
install -d -m 700 "$HOME/Library/LaunchAgents"
sed "s|/Users/REPLACE_ME|$HOME|g" deploy/com.litechecker.agent.plist \
  > "$HOME/Library/LaunchAgents/com.litechecker.agent.plist"
chmod 600 "$HOME/Library/LaunchAgents/com.litechecker.agent.plist"
# Отредактируйте REPLACE_WITH_AGENT_ID и collector.example.invalid:
open -e "$HOME/Library/LaunchAgents/com.litechecker.agent.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.litechecker.agent.plist"
launchctl kickstart -k "gui/$(id -u)/com.litechecker.agent"
launchctl print "gui/$(id -u)/com.litechecker.agent"
```

`RunAtLoad`, `KeepAlive` и `ThrottleInterval=10` обеспечивают запуск и backoff; внутренний планировщик агента всё равно не допускает пересечения циклов.

## Расписание, подписка и доставка

Первый цикл начинается сразу. Следующий старт происходит через 600 секунд после завершения предыдущего; пропущенные циклы не догоняются и не пересекаются. Collector считает агент offline примерно через 1500 секунд без валидного отчёта и один раз уведомляет; следующий отчёт создаёт одно recovery-уведомление.

Перед проверками каждого цикла агент заново скачивает подписку. Только полностью валидный непустой ответ становится списком этого цикла. Все удаления, включая удаление более половины адресов, применяются сразу; VPN и SNI строятся только из нового ответа. Предыдущий снимок хранится для сравнения добавлений, удалений и изменений, а не как запасной список проверок. Ошибка загрузки, невалидный или пустой ответ дают `UNAVAILABLE`: старые адреса не проверяются, сообщения «Всё доступно» нет.

Каждый запрос содержит новый случайный query-параметр и заголовки `Cache-Control: no-cache, no-store, max-age=0`, `Pragma: no-cache`. Ответ с положительным, некорректным или неоднозначным `Age`, а также `304`, не принимается. Исходные параметры URL сохраняются; если провайдер подписывает весь query и запрещает дополнительные параметры, обновление завершится ошибкой без скрытого повтора старого URL. Это защита от использования локального/HTTP-кэша, **не гарантия актуальности базы самого API**: если сервер генерирует старый список как новый ответ, чекер не может обнаружить это без версии/времени обновления от провайдера. Изменение подписки уже после её загрузки попадёт в следующий цикл.

У агента сохраняется только самый новый недоставленный отчёт. Collector дедуплицирует `event_id`, но доставка имеет семантику at-least-once: при сбое между отправкой и подтверждением Telegram возможен визуальный дубль. Telegram-уведомления сначала попадают в durable outbox SQLite, отправляются по порядку и по частям. Исчерпавшие retry budget или постоянные ошибки переходят в dead letter, чтобы не блокировать новые сообщения.

При стандартном интервале отчёта 600 секунд лимит `100` pending-уведомлений на агента покрывает примерно 16 часов outage; глобальные лимиты `10000` уведомлений/`100000` chunks защищают SQLite от неограниченного роста. При достижении лимита новые события получают закрытый `503 collector-backpressure`, точный duplicate остаётся идемпотентно принимаемым, а admission автоматически возобновляется после ACK. Настраивайте `LC_MAX_PENDING_*` с учётом числа агентов и длительности допустимого Telegram outage, не отключая dead-letter cap.

Проверить и безопасно переочередить dead letter без вывода текста сообщения:

```bash
docker compose -f compose.example.yml exec -T collector python - <<'PY'
from datetime import UTC, datetime
from litechecker.collector.auth import AgentRegistry
from litechecker.collector.db import CollectorDB

registry = AgentRegistry.load("/run/secrets/agents.json")
db = CollectorDB("/var/lib/litechecker/collector.sqlite3", registry.identities)
for item in db.dead_letters():
    print(item.notification_id, item.kind, item.next_chunk, item.chunk_count, item.error_code)
# После устранения причины раскомментируйте нужный ID:
# db.requeue_dead_letter(123, datetime.now(UTC))
PY
```

Requeue идемпотентен и продолжает с первой неподтверждённой части, но caveat at-least-once остаётся.

## Логи и права

Логи CLI — однострочный структурированный JSON с закрытыми кодами событий. URL подписки, UUID VLESS, REALITY keys/short IDs, agent token, Telegram token и raw outbound/config не должны выводиться. Если сторонний supervisor пишет окружение или командную строку, это отдельный риск — поэтому секреты задаются файлами, а не CLI-аргументами.

Перед запуском минимально проверьте права так:

```bash
find secrets -type f -exec chmod 600 {} +
chmod 600 agents.json .env .env.agent .env.collector
chmod 700 secrets state state/collector state/tbilisi-agent
```

Private targets по умолчанию запрещены. `LC_ALLOW_PRIVATE_TARGETS=1` допустим только в контролируемой лаборатории: hostname остаётся доверенным входом для Xray.

## Обновление и rollback

Перед обновлением сохраните `agents.json` и secret-файлы, соберите новый image с lock-файлом и выполните одноразовый агентский цикл. Онлайн-backup SQLite обязательно делайте через SQLite backup API: простое копирование `collector.sqlite3` отдельно от `-wal`/`-shm` может дать несогласованный снимок.

```bash
set -euo pipefail
BACKUP_PATH="state/collector/collector-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
python3 scripts/backup_sqlite.py state/collector/collector.sqlite3 "$BACKUP_PATH"
python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); assert c.execute("PRAGMA integrity_check").fetchall()==[("ok",)]' "$BACKUP_PATH"
```

Затем заменяйте сначала collector, потом по одному агенту. Не запускайте две копии одного `LC_AGENT_ID` с разными state-каталогами.

Для rollback верните предыдущий digest image и перезапустите сервисы, не откатывая SQLite поверх более нового файла. Если новая версия изменила схему и обратная совместимость не подтверждена, восстановите проверенный backup только в остановленном collector:

```bash
set -euo pipefail
BACKUP_PATH=REPLACE_WITH_VALIDATED_BACKUP_PATH
docker compose -f compose.example.yml stop collector
python3 scripts/restore_sqlite.py "$BACKUP_PATH" state/collector/collector.sqlite3
# Скрипт валидирует backup, fsync-ит и атомарно заменяет main DB с mode 0600.
# Старые main (`collector.sqlite3`), WAL (`collector.sqlite3-wal`) и SHM
# (`collector.sqlite3-shm`) сначала перемещаются в rollback-файлы. При любой ошибке
# установки они возвращаются; rollback-файлы удаляются только после fsync и
# успешной integrity_check установленной базы.
python3 -c 'import sqlite3; c=sqlite3.connect("state/collector/collector.sqlite3"); assert c.execute("PRAGMA integrity_check").fetchall()==[("ok",)]'
docker compose -f compose.example.yml up -d collector
docker compose -f compose.example.yml exec collector python -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).read()"
```

## Диагностика

- Exit `2`: отсутствует/невалидна переменная, secret-файл пуст или токен не соответствует точному `lc_`-формату.
- `401` collector: ID отсутствует в реестре, токен не совпадает или report содержит другой ID.
- `422`: схема отчёта или последовательность некорректна; не редактируйте state вручную.
- `503`/неhealthy: проверьте доступность и права SQLite volume, `agents.json`, watchdog и число dead letters в `/healthz`.
- `UNAVAILABLE`: актуальный список не получен; проверки VPN/SNI пропущены. Проверьте HTTPS-доступ к подписке и ответ API. `STALE` может встречаться в старых отчётах/у старых агентов; обновлённый агент не использует кэш вместо нового списка.
- `UNKNOWN / AGENT_NETWORK`: сначала восстановите прямой интернет агента; это не доказательство падения VPN.
- `UNKNOWN / XRAY`: проверьте `LC_XRAY_BINARY` и точную версию `xray version`, не публикуя stderr с конфигурацией.
- `DOWN / VLESS_E2E`: прямой контроль и TCP прошли, но HTTPS через конкретный outbound — нет; сравните второй город и только затем меняйте серверную конфигурацию.
- Нет Telegram: проверьте chat/topic ID, права бота, durable outbox и dead letters; не делайте пробный вызов с токеном в URL командной строки.
