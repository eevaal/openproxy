# OpenProxy v0.3.1

[Русский](README.md) | [English](README.en.md) | [简体中文](README.zh-CN.md)

A local programmable HTTP forward proxy for testing controlled clients. Mock rules
return predefined responses without DNS resolution or an upstream connection.
The management API runs separately from the proxy.

## Installation and startup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync
uv run openproxy version
uv run openproxy config validate --config /absolute/path/settings.yaml
uv run openproxy start --config /absolute/path/settings.yaml
uv run openproxy status --config /absolute/path/settings.yaml
uv run openproxy doctor --config /absolute/path/settings.yaml
```

`start` runs in the foreground; stop it with Ctrl+C. The API listens on
127.0.0.1:8000 by default. Older YAML files remain compatible: omitting `proxy`
keeps the proxy disabled. For a new setup, create settings.yaml:

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

api.example.test does not need to resolve: mocks do not access the network.
`response.body` accepts JSON and text. Strings become plain text; objects, arrays
and numbers become JSON. `null` means an empty body. Final response status codes
range from 200 to 599; informational 1xx responses cannot be mocks. HEAD omits the
body while preserving its Content-Length; 204/205/304 have no body. A supplied
Content-Length is replaced with the calculated value. Hop-by-hop headers are
removed. Binary files are not supported in this version.

## Configuration and rules

Source priority: `--config` → `OPENPROXY_CONFIG` → config.yaml in the current
directory → defaults. An explicitly selected missing file, empty YAML, wrong
types and unknown fields are errors. Absolute paths do not depend on the working
directory; the reload child receives an absolute path. `{}` uses defaults.
Ports must be integers from 1 to 65535; an enabled proxy cannot use the API port.
Listener addresses must be IP addresses or localhost. Rule IDs must be unique
and contain only ASCII letters, digits, dots, hyphens and underscores.

Rules are evaluated by descending priority, then declaration order. The first
match wins; disabled rules are skipped. Omitted match fields impose no constraint.
Host matching is case-insensitive, IDNA-normalized and ignores a trailing dot;
IP addresses are normalized. Paths match exactly in encoded form: `/a%2Fb` is
different from `/a/b`. Query constraints are a mapping, for example:

```yaml
match:
  host: api.example.test
  path: /status
  query:
    mode: test
```

Query strings use form decoding: `+` means a space. Each specified key must have
exactly one matching value; additional keys are allowed. The forward action
cannot specify a response and relays the original request. If no rule matches,
`unmatched_action` applies (default: block/403).

`config show` and `/api/v1/config` expose a safe server/logging projection,
preserving the v0.2.1 contract. They intentionally exclude rules and mock bodies,
which may contain sensitive test data. Engine state has its own endpoint.
Configuration is fixed at startup; rule hot reload is not supported.

## Forwarding and CONNECT

To forward unmatched HTTP requests, explicitly set `unmatched_action: forward`
or add an `action: forward` rule. Internal destinations remain blocked. For a
local test upstream, explicitly set `allow_private_targets: true`. This weakens
the policy for all forwarding; use it only with trusted clients. OpenProxy does
not change system proxy settings.

```bash
curl --noproxy '' --proxy http://127.0.0.1:8080 https://example.com
```

This external example requires permitted forwarding and network access; project
tests do not run it. CONNECT requires `unmatched_action: forward` and a port in
`allowed_connect_ports`. The bidirectional TCP tunnel supports half-close,
does not decrypt TLS and does not modify certificates. HTTP path/method/query
inside TLS are invisible to the Rule Engine. HTTPS mocking is not implemented.
A future explicitly trusted test TLS endpoint could feed decrypted HTTP to the
same Rule Engine; no such endpoint or hidden MITM exists now.

## Architecture

FastAPI lifespan starts ProxyServer and stops it during shutdown. A proxy bind
failure aborts application startup, so the API does not report false readiness.
The CLI passes API bind settings to Uvicorn; standalone ASGI deployments must
set Uvicorn bind options separately. `--reload` is for development only: it
watches Python, not YAML. Address changes require a full restart.

- core/config.py: YAML, Pydantic, defaults and validation.
- rules/models.py and rules/engine.py: rules and deterministic selection.
- proxy/server.py: listener, connection limit, dispatch, statistics and shutdown.
- proxy/protocol.py: h11 events and hop-by-hop header filtering.
- proxy/forward.py: concurrent streaming upload/download with backpressure.
- proxy/network.py: DNS, destination policy and checked-IP connections.
- proxy/responses.py: JSON/text and mock HTTP response semantics.
- proxy/tunnel.py: CONNECT and bidirectional TCP relay.

The stack is asyncio + [h11](https://h11.readthedocs.io/en/latest/basic-usage.html).
h11 handles HTTP framing without a custom parser and is transport-independent.
Requests/responses stream in chunks up to 64 KiB without buffering entire bodies.
GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS, absolute/origin form, Content-Length and
chunked encoding are supported. CL+TE is rejected; h11 validates conflicting CL.
The upstream Host is built from the destination. Proxy authentication and
connection-nominated headers are not forwarded. Each HTTP connection serves one
request and closes. Keep-alive, pipelining, WebSocket/Upgrade, HTTP/2 and trailers
are not supported.

## Security and logging

Both listeners are local by default; the proxy is disabled and unknown requests
are blocked. An external proxy listener requires `allow_external_bind: true`.
This exposes an unauthenticated proxy: restrict access with a firewall. The API
also has no authentication and warns when configured on an external interface.

After DNS resolution, any private, loopback, link-local, multicast, unspecified
or other non-global answer blocks the connection unless private targets are
explicitly allowed. Both IPv4 and IPv6 are checked. Connections use checked
numeric IPs without resolving the hostname again. Redirects are not followed
automatically. There is no telemetry, external service dependency or TLS traffic
recording. `/health` service identification is not authentication.

Logs go to stderr; levels are DEBUG/INFO/WARNING/ERROR, formats text/json.
Global `--verbose` (DEBUG) and `--quiet` (WARNING) precede the command and cannot
be combined. Quiet hides successful confirmations but preserves errors and
explicitly requested data. Formatters use `LogRecord.getMessage()` without
removing args; root logging is unchanged and handlers are not duplicated.
OpenProxy does not log bodies, headers, query parameters or raw proxy errors.
DEBUG logs only the restricted rule ID. Access logs are disabled. Arbitrary
third-party library messages are not automatically scrubbed of secrets.

## API and statistics

| GET | Purpose |
| --- | --- |
| /health | Name, version, healthy status |
| /api/v1/info | Application capabilities |
| /api/v1/config | Safe configuration projection |
| /api/v1/proxy/status | enabled and running |
| /api/v1/proxy/stats | Process counters |
| /docs | OpenAPI UI |

Counters: active_connections, total_connections, mock_responses,
forwarded_requests, blocked_requests, errors. Updates contain no await and run
in one event loop. Total includes rejected connections; active includes HTTP and
CONNECT. Mock/block/forward count selected actions, not guaranteed deliveries;
errors count processing failures. Byte counts are not published. Counters reset
on restart and are not shared between processes.

## Diagnostics and troubleshooting

CLI exit codes: 0 for success; 1 for an unavailable server, unhealthy engine or
bind failure; 2 for configuration or argument errors. Doctor prints PASS/WARN/FAIL.
A stopped server with a free port is WARN and exits 0. A running OpenProxy is not
considered a port conflict. With the proxy enabled, status also checks engine
state through the API; doctor checks its state or whether its port can bind.
Checks do not reserve ports; state may change immediately afterwards.

- 403: no permitting rule or a destination denied by policy.
- 400: malformed request or ambiguous framing.
- 502: connection or upstream protocol failure.
- 503: max_connections reached.
- 504: connect/read/write timeout.
- Startup port error: stop the conflicting process or choose another port.

On shutdown, the listener stops accepting connections. Active tasks get
shutdown_timeout to finish; remaining tasks are cancelled and both transports
close. An error after a response begins closes the stream without a second HTTP
response.

## Checks and learning

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check src tests
uv run mypy
```

tests/test_proxy.py uses real local HTTP/TCP servers and ephemeral ports. Tests
cover streaming, methods, headers, mocks without upstream access, CONNECT,
errors, security and shutdown. DNS policy tests use stubs without external
connections. Start reading rules/models.py → rules/engine.py → proxy/responses.py
→ proxy/server.py, then streaming forwarding and network.py. Existing
CLI/API/config/logging tests remain.

Limitations: no binary file mocks, keep-alive, HTTPS mocking, persistent
statistics or rule-editing UI. Mock bodies already reside in YAML in memory;
do not use YAML for huge fixtures. There is no rate limit or total request-count
limit over time. read_timeout bounds waiting for the next portion; the total
request_timeout is 300 seconds by default, including CONNECT. Increase it up to
86400 for long transfers/tunnels. This is a local trusted-client tool, not a
hardened public proxy gateway.

## Preparing changes for a commit

```bash
make check   # lockfile, Ruff lint/format, mypy, pytest, YAML example
make build   # wheel and source distribution in dist/
```

Without make, run the individual Makefile commands. Use `make format` to format
code, then rerun `make check`. `--locked` prevents silent dependency updates
during checks. Tool caches, build outputs and local settings.yaml are Git-ignored.

Run the safe example without creating a local file:

```bash
uv run openproxy start --config examples/mock.yaml
curl --noproxy '' --proxy http://127.0.0.1:8080 http://api.example.test/status
```

examples/mock.yaml is intended for sharing; keep secrets and personal settings
in local settings.yaml.

## Patch release v0.3.1

The audit and regressions are documented in [AUDIT-0.3.1.md](AUDIT-0.3.1.md).

- Host and CONNECT authority are validated before URL normalization: userinfo,
  path/query/fragment, scoped IPv6, empty ports and port 0 are rejected.
  Absolute-form still uses URL authority; a different valid Host is allowed.
  Origin-form preserves `//` in the path. Malformed DNS names are rejected.
- Incoming/upstream headers are limited to 100 fields and 16 KiB normalized size.
  h11 also limits incomplete blocks. Event parsing deadlines do not renew for
  each TCP byte: slow headers expire after read_timeout.
- request_timeout bounds the entire HTTP exchange or CONNECT (300 seconds).
  Errors/cancellation release the slot. Up to 16 rejection tasks are allowed
  beyond max_connections; further connections are reset without a 503 response.
- Proxy-Connection is included when filtering hop-by-hop fields.
- IPv6 site-local and NAT64/6to4/Teredo are conservatively blocked when
  allow_private_targets is false; mapped IPv6 is checked using its embedded IPv4.
  Explicit private-target permission remains a policy relaxation for trusted use.
- Mocks reject non-finite JSON, invalid UTF-8 text and response headers duplicated
  with different casing. Text defaults to charset=utf-8.
- Background task exceptions are retrieved without tracebacks or sensitive
  details; stalled transport closure ends in abort.

Stricter malformed-request validation is intentional. Valid v0.3.0 configurations
remain compatible. Existing HTTP/HTTPS limitations remain. This is not a public
gateway security certification; both the API and proxy remain unauthenticated.
