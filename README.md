# OpenProxy v0.3.1

Локальный программируемый HTTP forward proxy для тестирования контролируемых
клиентов. Mock-правила возвращают подготовленные ответы без DNS и подключения
к upstream. Управляющий API работает отдельно от прокси.

## Установка и запуск

Требуются Python 3.12+ и [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync
uv run openproxy version
uv run openproxy config validate --config /absolute/path/settings.yaml
uv run openproxy start --config /absolute/path/settings.yaml
uv run openproxy status --config /absolute/path/settings.yaml
uv run openproxy doctor --config /absolute/path/settings.yaml
```

`start` работает в foreground, остановка — Ctrl+C. По умолчанию API слушает
127.0.0.1:8000. Старые YAML остаются совместимыми: отсутствующий раздел proxy
означает выключенный прокси. Для нового сценария создайте settings.yaml:

```yaml
server:
  host: 127.0.0.1
  port: 8000
proxy:
  enabled: true
  host: 127.0.0.1
  port: 8080
  connect_timeout: 10
  read_timeout: 30
  request_timeout: 300
  shutdown_timeout: 5
  max_connections: 100
  unmatched_action: block
  allowed_connect_ports: [443]
  allow_private_targets: false
  allow_external_bind: false
logging:
  level: INFO
  format: text
rules:
  - id: device-status
    enabled: true
    priority: 100
    match:
      method: GET
      host: api.example.test
      path: /v1/device/status
    action: mock
    response:
      status: 200
      headers:
        Content-Type: application/json
      body:
        status: ok
        connected: true
      delay: 0
  - id: deny-admin
    priority: 200
    match:
      path: /admin
    action: block
    response:
      status: 403
      body: Access denied
```

```bash
curl --noproxy '' --proxy http://127.0.0.1:8080 \
  http://api.example.test/v1/device/status
```

Имя api.example.test не обязано разрешаться: mock не обращается в сеть.
`response.body` поддерживает JSON и текст; строка становится plain text, объект,
массив или число — JSON. `null` означает пустое тело. Статусы конечного ответа
допустимы от 200 до 599; informational 1xx не являются mock-ответами. HEAD не
передаёт тело, сохраняя его Content-Length; 204/205/304 передаются без тела.
Пользовательский Content-Length заменяется вычисленным. Hop-by-hop заголовки
удаляются. Бинарные файлы в этой версии не поддерживаются.

## Конфигурация и правила

Порядок источников: `--config` → `OPENPROXY_CONFIG` → config.yaml в текущем
каталоге → defaults. Явный отсутствующий файл, пустой YAML, неверные типы и
неизвестные поля — ошибки. Абсолютный путь независим от рабочего каталога;
дочерний процесс reload получает абсолютный путь. `{}` использует defaults.
Порты — целые числа 1–65535; включённый proxy не может использовать порт API.
Адрес listener — IP либо localhost. У каждого правила уникальный ID из ASCII
букв, цифр, точки, дефиса и подчёркивания.

Правила обрабатываются по убыванию priority, затем по порядку объявления.
Первое совпадение побеждает; disabled пропускаются. Отсутствующее поле match
не ограничивает запрос. Host сравнивается без регистра, с IDNA-нормализацией,
без завершающей точки; IP нормализуется. Path сравнивается точно в encoded
форме: `/a%2Fb` отличается от `/a/b`. Query задаётся словарём, например:

```yaml
match:
  host: api.example.test
  path: /status
  query:
    mode: test
```

Query декодируется по правилам form query: `+` — пробел. Указанный ключ должен
иметь ровно одно совпадающее значение; дополнительные ключи разрешены.
Действие forward не принимает response и пересылает исходный запрос.
Отсутствие совпадения применяет unmatched_action (по умолчанию block/403).

`config show` и `/api/v1/config` выводят безопасную проекцию server/logging,
сохраняющую контракт v0.2.1. Они намеренно не экспортируют правила и mock bodies:
в тех могут быть чувствительные тестовые данные. Состояние engine проверяется
отдельным endpoint. Конфигурация фиксируется при старте; hot reload правил нет.

## Forward и CONNECT

Для пересылки неизвестных HTTP-запросов явно установите unmatched_action: forward
либо создайте правило action: forward. Внутренние назначения всё равно запрещены.
Для локального upstream в тестовой среде явно включите allow_private_targets:
true. Это ослабляет защиту для всего forwarding, используйте только с доверенными
клиентами. Системные настройки прокси программа не меняет.

```bash
curl --noproxy '' --proxy http://127.0.0.1:8080 https://example.com
```

Внешний пример требует разрешённого forwarding и сетевого доступа; тесты проекта
его не выполняют. CONNECT разрешён только при unmatched_action: forward и к
allowed_connect_ports. TCP-туннель передаёт байты в обе стороны, поддерживает
half-close, не расшифровывает TLS и не меняет сертификаты. Path/method/query
внутри TLS недоступны Rule Engine. HTTPS mocking не реализован. Будущий явно
доверенный тестовый TLS endpoint может передавать расшифрованный HTTP тому же
Rule Engine; сейчас такой endpoint отсутствует, скрытого MITM нет.

## Архитектура

FastAPI lifespan запускает ProxyServer и останавливает его при shutdown. Ошибка
привязки proxy прерывает startup всего приложения; API не сообщает ложную
готовность. CLI передаёт API-параметры Uvicorn; при самостоятельном ASGI-запуске
параметры привязки Uvicorn указываются отдельно. `--reload` только для разработки:
наблюдает Python, не YAML; изменение адресов требует полного перезапуска.

- core/config.py: YAML, Pydantic, defaults и валидация.
- rules/models.py и rules/engine.py: правила и детерминированный выбор.
- proxy/server.py: listener, лимит соединений, dispatch, статистика, shutdown.
- proxy/protocol.py: h11 events и фильтрация hop-by-hop headers.
- proxy/forward.py: одновременный streaming upload/download с backpressure.
- proxy/network.py: DNS, политика назначения, подключение к проверенному IP.
- proxy/responses.py: JSON/text и HTTP-семантика mock-ответов.
- proxy/tunnel.py: CONNECT и двусторонний TCP relay.

Выбран asyncio + [h11](https://h11.readthedocs.io/en/latest/basic-usage.html):
h11 разбирает HTTP framing без собственного парсера и не привязан к transport.
Request/response передаются блоками до 64 КиБ, без загрузки целого тела.
Поддерживаются GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS, absolute/origin form,
Content-Length и chunked. CL+TE отвергается; h11 проверяет конфликтующие CL.
Host upstream строится из назначения, proxy-auth и connection-nominated headers
не пересылаются. Каждое HTTP-соединение обслуживает один запрос и закрывается.
Keep-alive, pipelining, WebSocket/Upgrade, HTTP/2 и trailers не поддерживаются.

## Безопасность и логирование

По умолчанию оба listener локальны, proxy выключен, unknown requests блокируются.
Для внешнего listener proxy требуется allow_external_bind: true; это открывает
неаутентифицированный прокси — ограничьте доступ файрволом. API тоже не имеет
аутентификации; его внешний интерфейс вызывает предупреждение.

DNS проверяется после разрешения: если хотя бы один ответ является private,
loopback, link-local, multicast, unspecified или иным non-global адресом,
соединение запрещается (без allow_private_targets). IPv4 и IPv6 проверяются.
Подключение выполняется к числовому проверенному IP без повторного DNS.
Redirect не выполняется автоматически. Телеметрии, внешних сервисов и записи
TLS-трафика нет. Идентификация `/health` не является аутентификацией.

Логи идут в stderr; уровни DEBUG/INFO/WARNING/ERROR, format text/json. Глобальные
`--verbose` (DEBUG) и `--quiet` (WARNING) передаются до команды; вместе запрещены.
Quiet скрывает успешные подтверждения, сохраняя ошибки и явно запрошенные данные.
Форматтер использует `LogRecord.getMessage()` без удаления args; root logger не
меняется, обработчики не дублируются. OpenProxy не логирует body, заголовки,
query или сырые ошибки proxy. DEBUG пишет только ограниченный ID правила.
Access-log выключен. Произвольные сообщения сторонних библиотек автоматически
от секретов не очищаются.

## API и статистика

| GET | Назначение |
| --- | --- |
| /health | Имя, версия, healthy |
| /api/v1/info | Возможности приложения |
| /api/v1/config | Безопасная проекция конфигурации |
| /api/v1/proxy/status | enabled и running |
| /api/v1/proxy/stats | Счётчики процесса |
| /docs | OpenAPI UI |

Счётчики: active_connections, total_connections, mock_responses,
forwarded_requests, blocked_requests, errors. Изменяются без await в одном event
loop. Total включает rejected connections; active включает HTTP и CONNECT.
Mock/block/forward считают выбранные действия, а не гарантированно доставленные
ответы; errors считают сбои обработки. Байты не публикуются. После перезапуска
статистика обнуляется; для нескольких процессов общей статистики нет.

## Диагностика и troubleshooting

Коды CLI: 0 — успех, 1 — сервер недоступен/engine неисправен/ошибка bind,
2 — ошибка конфигурации или аргументов. Doctor показывает PASS/WARN/FAIL,
неработающий сервер со свободным портом — WARN и 0. Работающий OpenProxy не
считается конфликтом порта. При включённом proxy status дополнительно проверяет
engine через API, doctor проверяет состояние или возможность bind proxy port.
Проверки не резервируют порт; состояние может измениться сразу после проверки.

- 403: нет разрешающего правила или назначение запрещено политикой.
- 400: некорректный запрос/неоднозначное framing.
- 502: ошибка подключения либо upstream-протокола.
- 503: достигнут max_connections.
- 504: connect/read/write timeout.
- Ошибка порта при старте: остановите конфликтующий процесс или смените порт.

При shutdown listener перестаёт принимать запросы, активным задачам даётся
shutdown_timeout, оставшиеся отменяются с закрытием обоих transport. Ошибка после
начала ответа приводит к закрытию потока, второй HTTP-ответ не отправляется.

## Проверки и обучение

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check src tests
uv run mypy
```

tests/test_proxy.py использует настоящие локальные HTTP/TCP-серверы и ephemeral
ports. Тесты проверяют streaming, методы, заголовки, mock без upstream, CONNECT,
ошибки, безопасность и shutdown. DNS policy отдельно проверяется подменами без
внешних соединений. Начните изучение с rules/models.py → rules/engine.py →
proxy/responses.py → proxy/server.py; затем streaming forward и network.py.
Существующие CLI/API/config/logging тесты сохранены.

Ограничения: без binary file mocks, keep-alive, HTTPS mocking, постоянной
статистики и UI редактирования правил. Mock тела уже находятся в YAML в памяти;
не используйте YAML для огромных fixtures. Нет ограничения скорости/общего
числа запросов во времени. read_timeout — таймаут ожидания очередной порции,
в дополнение действует общий request_timeout (по умолчанию 300 секунд,
включая CONNECT). Для длительных загрузок/туннелей его можно увеличить до 86400. Это локальный инструмент для доверенных клиентов,
не защищённый публичный proxy gateway.


## Подготовка изменений к коммиту

```bash
make check   # lock-файл, Ruff lint/format, mypy, pytest, пример YAML
make build   # wheel и source distribution в dist/
```

Без make можно выполнить команды из Makefile по отдельности. Для автоматического
форматирования используйте `make format`, затем снова `make check`.
`--locked` не позволяет незаметно обновить зависимости во время проверок.
Кеши инструментов, результаты сборки и локальный settings.yaml исключены из Git.

Готовый безопасный пример можно запустить без создания локального файла:

```bash
uv run openproxy start --config examples/mock.yaml
curl --noproxy '' --proxy http://127.0.0.1:8080 http://api.example.test/status
```

Изменения в examples/mock.yaml предназначены для совместного использования;
секреты и личные настройки храните в локальном settings.yaml.


## Patch release v0.3.1

Аудит и регрессионные тесты описаны в AUDIT-0.3.1.md.

- Host и CONNECT authority валидируются до URL-нормализации: запрещены userinfo,
  path/query/fragment, scoped IPv6, пустой порт и порт 0. Absolute-form по-прежнему
  использует authority URL; отличающийся, но корректный Host разрешён. Origin-form
  сохраняет `//` как часть пути. Произвольные некорректные DNS-имена запрещены.
- Входящие и upstream заголовки ограничены 100 полями и 16 КиБ нормализованного
  размера. h11 дополнительно ограничивает неполный блок. Deadline разбора одного
  события не продлевается каждым TCP-байтом: slow headers завершаются по read_timeout.
- Новый request_timeout ограничивает весь HTTP exchange или CONNECT (300 секунд).
  Слот освобождается после ошибки/отмены. Помимо max_connections допускается не
  более 16 служебных задач отказа; последующие соединения сбрасываются без 503.
- Proxy-Connection также учитывается при исключении hop-by-hop полей.
- IPv6 site-local и NAT64/6to4/Teredo блокируются консервативно при allow_private_targets: false;
  mapped IPv6 проверяется по вложенному IPv4. Явное разрешение private targets
  остаётся ослаблением политики для доверенной локальной среды.
- Mock отвергает non-finite JSON, невалидный UTF-8 text и дубли response headers
  с разным регистром. Для text автоматически указывается charset=utf-8.
- Ошибки фоновых задач извлекаются без traceback и чувствительных деталей;
  зависшее закрытие transport завершается abort.

Строгость проверки некорректных запросов усилена намеренно; валидные конфигурации
v0.3.0 совместимы. Существующие ограничения HTTP/HTTPS не изменились. Это не
сертификация безопасности публичного gateway; API и proxy остаются без auth.
