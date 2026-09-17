# Протокол happd: разбор и headless-подключение

Happ (happ.su) — GUI-клиент для Xray с TUN-режимом. Вся работа идёт через
привилегированный демон `happd`, а GUI лишь рисует окно и отдаёт команды.
Этот документ описывает протокол GUI↔демон, как мы его сняли и как на его
основе работает headless-подключение в waybar-vpn-manager.

## Архитектура Happ

```
┌────────────┐   unix-socket    ┌───────────┐   stdin/stdout (JSON-конфиг)   ┌──────┐
│  Happ GUI  │ ◄──────────────► │  happd    │ ◄────────────────────────────► │ xray │
│ (Qt, user) │  /tmp/happd.sock │  (root)   │  spawn + pipes + signals       │(root)│
└────────────┘                  └───────────┘                                └──────┘
                                     │ manages also: sing-box, tun2proxy
```

Ключевой факт: **GUI не подключает VPN сам**. Он собирает конфиг ядра в памяти
(из подписки) и просит демон запустить процесс. Демон держит процессы, шлёт
их stdout/stderr клиенту событиями и убивает их при отключении владельца.

## Формат фрейма

Оба направления — одинаковые length-prefixed фреймы:

```
frame = 4 байта (big-endian длина) + UTF-8 JSON payload
```

Пример (hex-дамп начала): `\0\0\0q{"action":"get-privilege","request-id":"req_182"}` —
длина 0x71 = 113 байт.

## Каталог экшенов (снят с живого трафика)

### Клиент → демон

| action | поля | ответ |
|---|---|---|
| `get-privilege` | `request-id` | `{"privilege-level":2,"status":"success"}` (2 = root) |
| `list` | — | `{"processes":[{"process-id":"xray-core","running":true}],"status":"success"}` |
| `status` | `process-id` | `{"running":bool,...}` |
| `stop` | `process-id` | статус остановки |
| `start` | см. ниже | `{"status":"started"}` + событие `started` |
| `heartbeat` | — | keepalive сессии |
| `register-proxy-restore` / `clear-proxy-restore` | `gui-exe-path` | в daemon 4.3.0 — `Unknown action` |

### `start` — главный экшен

```json
{
  "action": "start",
  "request-id": "req_183",
  "process-id": "xray-core",
  "executable": "/opt/happ/bin/core/xray",
  "arguments": [],
  "environment": {"XRAY_LOCATION_ASSET": "~/.local/share/Happ/routing/<sub>/<подписка>"},
  "stdin-data": "<сериализованный JSON-конфиг xray>"
}
```

- `stdin-data` — **полный конфиг xray целиком** (inbounds: socks/http/tun,
  outbounds: vless+reality, routing, dns). Демон пишет его в stdin процесса.
- `environment` — путь к geoip/geosite (`XRAY_LOCATION_ASSET`), зависит от
  подписки.
- `request-id` — демон эхает его в ответе; клиент матчит ответы к запросам.

### Демон → клиент (события, multicast)

```json
{"event":"connected","daemon-version":"4.3.0","privilege-level":2}
{"event":"push-token","token":"<FCM-токен Google>"}     ← игнорируем
{"event":"started","process-id":"xray-core","timestamp":"..."}
{"event":"stdout","process-id":"xray-core","data":"Xray 26.7.28 ..."}
{"event":"stderr","process-id":"xray-core","data":"..."}
{"event":"stopped","process-id":"xray-core"}
```

## Как это снимали

1. **Прокси на сокете** (`socat`/python между GUI и демоном) — провал: при
   перезапуске GUI новый user-level `happd` делает `unlink(/tmp/happd.sock)`
   и сносит чужой сокет. Демон может пересоздаваться — прокси отваливается.
2. **strace демона** — рабочий способ: `sudo strace -f -p <happd> -e trace=read,write,sendmsg,recvmsg -s 65536`.
   Демон в простое молчит, фреймы видны целиком в read/write. Из дампа
   извлекается `stdin-data` экшена `start`:
   `scripts/happd-extract-config.py /tmp/happd.strace ~/.config/happ-capture/xray-configs.json`
   (файл конфигов — `chmod 600`: внутри VLESS-uuid и reality-ключи).

## Главный подводный камень: владение сессией

Демон привязывает запущенный процесс к клиентскому соединению, которое его
запустило (в бинарнике: `reclaim-session-processes`). Эксперимент:

- отправили `start`, держим сокет открытым → туннель жив;
- закрыли сокет → демон тут же убрал интерфейс `happ-xray`.

Поэтому «одноразовый» запрос недостаточен — нужен **keeper-процесс**:
подключается к happd, шлёт `start` и держит сокет открытым, пока туннель жив
(выходит по событию `stopped` или исчезновению интерфейса). Реализация:
`run_keeper()` в `src/providers/happ.py`, точка входа `vpn_manager.py --happ-keeper`.

## Headless-подключение в менеджере

1. `~/.config/happ-capture/xray-configs.json` — {имя сервера (remarks): xray-конфиг},
   пополняется скриптом-экстрактором после захвата.
2. Пользователь выбирает «Connect» в waybar → `HappProvider.connect()`:
   - GUI запущен → просим нажать Connect в окне (старое поведение);
   - иначе ищем captured-конфиг для `_last_server_name()` (из `Happ.conf`,
     нечёткое совпадение по подстроке) → спавним keeper → ждём вердикта
     из `~/.local/state/vpn-manager/happ-keeper.json` (до 6 с);
   - нет конфига / ошибка → фолбэк на запуск GUI.
3. Disconnect шлёт `stop` одноразовым запросом (не привязан к сессии) —
   keeper сам замечает и завершается.

Ограничения и заметки:
- Конфиг живёт, пока сервер не сменил ключи/порты; после ротации ключей на
  стороне провайдера перезахвати: strace демона → Connect/Disconnect в GUI →
  `scripts/happd-extract-config.py`.
- Список серверов в меню = захваченные конфиги (+ последний использованный).
  Полный список подписки лежит в `~/.config/Happ/subs.db` в зашифрованном
  виде (AES-GCM; тег — в колонке `tag`, блоб — base64). Реверс ключа
  предпринимался и не завершён (см. research-инструменты ниже): ASCII-ключей
  в бинарнике нет, в памяти GUI рядом с объектом БД ключа не нашлось, EVP-
  танки OpenSSL подаются через слоты `.data` (нужен дальнейший разбор).
  Инструменты: `scripts/subs-db-keysearch.py`, `scripts/subs-db-keymem.py`,
  `scripts/happ-re-aes.py`, `scripts/happ-dump-subscription.py`,
  `scripts/happ-mem-census.py`.
- Переключение серверов из менеджера работает: connect останавливает
  текущий процесс (`stop`) и поднимает новый через keeper.
- GUI, запущенный параллельно, корректно видит состояние (читает тот же
  happd): Connect/Disconnect в любом интерфейсе синхронизированы.

## Приватность

- Файл захваченных конфигов содержит приватные ключи доступа к серверам —
  права 600, не коммитить.
- `/tmp/happd.strace` содержит те же ключи + FCM-токен — удалить после анализа:
  `rm /tmp/happd.strace`.
- Демон шлёт каждому клиенту `push-token` (Google Firebase) — Happ привязан
  к push-уведомлениям; менеджер токен игнорирует.
