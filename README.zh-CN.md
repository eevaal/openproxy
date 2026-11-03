# OpenProxy v0.4.0

[Русский](README.md) | [English](README.en.md) | [简体中文](README.zh-CN.md)

用于测试受控客户端的本地可编程 HTTP 正向代理。Mock 规则直接返回预设响应，
不解析 DNS，也不连接上游服务器。管理 API 与代理使用独立的监听端口。

## 安装与启动

需要 Python 3.12+ 和 [uv](https://docs.astral.sh/uv/getting-started/installation/)。

```bash
uv sync
uv run openproxy version
uv run openproxy config validate --config /absolute/path/settings.yaml
uv run openproxy start --config /absolute/path/settings.yaml
uv run openproxy status --config /absolute/path/settings.yaml
uv run openproxy doctor --config /absolute/path/settings.yaml
```

`start` 在前台运行，按 Ctrl+C 停止。API 默认监听 127.0.0.1:8000。
兼容旧版 YAML：缺少 proxy 配置时，代理保持关闭。新配置可保存为 settings.yaml：

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

api.example.test 无需能够解析：mock 不访问网络。`response.body` 支持 JSON 和文本；
字符串作为纯文本，对象、数组及数字作为 JSON，`null` 表示空响应体。
最终响应状态码范围为 200–599，1xx 信息响应不能作为 mock。HEAD 不发送响应体，
但保留对应的 Content-Length；204/205/304 不发送响应体。自定义 Content-Length
会被实际计算值替换，逐跳头会被移除。本版本不支持二进制文件响应。

## 配置与规则

配置优先级：`--config` → `OPENPROXY_CONFIG` → 当前目录中的 config.yaml → 默认值。
显式指定但不存在的文件、空 YAML、错误类型和未知字段都会报错。绝对路径不依赖
工作目录，reload 子进程会收到绝对路径。`{}` 使用默认值。端口必须是 1–65535
之间的整数；启用的代理不能使用 API 端口。监听地址必须是 IP 地址或 localhost。
规则 ID 必须唯一，仅允许 ASCII 字母、数字、点、连字符和下划线。

规则按 priority 降序处理，同优先级按声明顺序处理。第一个匹配项生效，禁用规则
被跳过；省略的 match 字段不施加限制。Host 匹配不区分大小写，执行 IDNA 规范化，
忽略末尾的点；IP 地址也会规范化。Path 按编码后的形式精确比较：`/a%2Fb` 与
`/a/b` 不同。Query 条件使用映射，例如：

```yaml
match:
  host: api.example.test
  path: /status
  query:
    mode: test
```

Query 按表单查询字符串规则解码，`+` 表示空格。指定的键必须恰好有一个匹配值；
允许其他额外键。forward 动作不能指定 response，它转发原始请求。没有匹配规则时
使用 unmatched_action，默认是 block/403。

`config show` 和 `/api/v1/config` 仅提供安全的 server/logging 配置视图，保持
v0.2.1 的接口契约。规则和 mock 响应体可能包含敏感测试数据，因此不会导出。
引擎状态通过独立端点查询。配置在启动时固定，不支持规则热重载。

## 转发与 CONNECT

要转发未匹配的 HTTP 请求，必须显式设置 `unmatched_action: forward`，或添加
`action: forward` 规则。内部目标仍然被禁止。测试本地上游服务器时，需要显式设置
`allow_private_targets: true`。这会放宽所有转发的访问策略，只应与可信客户端一起
使用。OpenProxy 不修改系统代理设置。

```bash
curl --noproxy '' --proxy http://127.0.0.1:8080 https://example.com
```

以上外部示例需要允许转发并具有网络访问权限，项目测试不会执行该请求。
普通 CONNECT 仅在 unmatched_action 为 forward 且目标端口位于 allowed_connect_ports
中时允许。TCP 隧道双向传输字节，支持半关闭，不解密 TLS，也不修改证书。
普通 TLS 隧道内部的 HTTP path/method/query 对 Rule Engine 不可见。

## 受控测试客户端的 HTTPS 检查

启用 `proxy.https_inspection.enabled`，并在 `hosts` 中列出确切的 DNS 名称。
检查功能仅用于已启用的环回代理。启用检查时，监听地址 `localhost` 会绑定到
127.0.0.1。所有 CONNECT 仍须使用 `allowed_connect_ports` 允许的端口。
名单以外的主机遵循原有 CONNECT 策略。对于名单内的主机，即使配置了
`unmatched_action: block`，OpenProxy 也会接受 CONNECT，与客户端建立 TLS，
然后对解密后的 HTTP 请求应用规则。

使用 `certificate_file` 提供 PEM 服务器证书或证书链，并通过
`private_key_file` 指定本地未加密的私钥。私钥权限须为 0600 或更严格。
相对路径以 YAML 文件所在目录为基准。证书须在有效期内，与私钥匹配，
并为每个检查主机包含确切的 DNS SAN。一个证书可以包含多个名称。
请在测试客户端中显式配置证书信任。使用证书固定的客户端需要通过其
受支持的测试设置来信任或固定测试证书。

检查支持 TLS 1.2 和 1.3，ALPN 声明 HTTP/1.1。CONNECT authority、SNI
和 TLS 内的 HTTP authority 必须一致。每个检查连接处理一个 HTTP 请求。
`handshake_timeout` 默认为 5 秒，包含在总 `request_timeout` 内。
普通 CONNECT 隧道保留 TCP 半关闭行为。

匹配 mock 时，代理在接收请求后通过原 TLS 连接返回响应。转发时，代理检查
DNS 结果，再连接通过检查的数字 IP。上游 SNI 和主机名校验使用 CONNECT 主机名。
上游证书按照 OpenSSL 默认信任根进行验证，也可通过 `upstream_ca_file` 添加
本地测试上游的信任证书。访问私有上游地址还需设置 `allow_private_targets: true`。

在仓库根目录运行以下命令。OpenSSL 需支持 `-addext`。生成命令需要新建
`certs` 目录，保留已有目录。

```bash
mkdir -m 700 certs && (
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=api.example.test' \
    -addext 'subjectAltName=DNS:api.example.test' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -keyout certs/test.key -out certs/test.crt
)
uv run openproxy doctor --config examples/https-mock.yaml
uv run openproxy start --config examples/https-mock.yaml
```

在另一个终端发送请求，并通过 `--cacert` 显式指定信任证书。

```bash
curl --noproxy '' --proxy http://127.0.0.1:8080 \
  --cacert certs/test.crt -H 'Content-Type: application/json' \
  --data '{}' https://api.example.test/api/v1/device/check
curl --noproxy '*' http://127.0.0.1:8000/api/v1/proxy/stats
```

预期 JSON 为 `{"success":true,"status":"active"}`。在新启动的进程中，
`https_mock_responses` 应为 1，`forwarded_requests` 应为 0。
[示例配置](examples/https-mock.yaml)

TLS 失败时请检查 DNS SAN、有效期、客户端信任、SNI 和私钥权限。
`doctor` 检查证书文件及配置。统计 API 提供 `https_inspection_connections`、
`https_mock_responses`、`tls_handshake_failures` 和 `https_forwarding_errors`。
上游证书验证失败返回 502。公开配置视图保留原有 server 和 logging 字段。

## 架构

FastAPI lifespan 启动 ProxyServer，并在关闭时停止它。代理端口绑定失败会中止
整个应用启动，API 不会错误地报告已就绪。CLI 将 API 监听参数传给 Uvicorn；
独立运行 ASGI 时必须另行设置 Uvicorn 的绑定参数。`--reload` 仅用于开发，监视
Python 文件而非 YAML；更改监听地址需要完整重启。

- core/config.py：YAML、Pydantic、默认值与校验。
- rules/models.py 和 rules/engine.py：规则模型与确定性的选择逻辑。
- proxy/server.py：监听、连接限制、分发、统计与关闭。
- proxy/protocol.py：h11 事件与逐跳头过滤。
- proxy/forward.py：带背压的并发流式上传和下载。
- proxy/network.py：DNS、目标访问策略以及连接已验证的 IP。
- proxy/responses.py：JSON/文本及 mock 响应的 HTTP 语义。
- proxy/tunnel.py：CONNECT 与双向 TCP 转发。

网络栈采用 asyncio + [h11](https://h11.readthedocs.io/en/latest/basic-usage.html)。
h11 负责 HTTP 消息分帧，无需自行实现解析器，也不依赖特定传输层。请求和响应
以不超过 64 KiB 的块传输，不将整个响应体或请求体缓存在内存中。
支持 GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS、absolute-form、origin-form、
Content-Length 和 chunked。CL+TE 会被拒绝，冲突的 CL 由 h11 校验。上游 Host
根据目标地址重新生成，不转发代理认证头及 Connection 指定的头。每条 HTTP
连接仅处理一个请求后关闭。不支持 keep-alive、流水线、WebSocket/Upgrade、HTTP/2
和 trailers。

## 安全与日志

默认情况下两个监听端口均为本地地址，代理关闭，未知请求被阻止。要在外部接口
监听代理，必须设置 `allow_external_bind: true`。这将暴露一个无认证代理，请使用
防火墙限制访问。API 同样没有认证，配置为外部接口时会发出警告。

DNS 解析后会检查所有地址：除非显式允许私有目标，否则只要任意结果为私有、
回环、链路本地、组播、未指定或其他非全局地址，就会拒绝连接。IPv4 和 IPv6
均会检查。连接使用已验证的数字 IP，不再次解析原始域名。不自动跟随重定向。
没有遥测、外部服务依赖或 TLS 流量记录。`/health` 的服务识别不是身份认证。

日志写入 stderr，支持 DEBUG/INFO/WARNING/ERROR 和 text/json。全局选项
`--verbose`（DEBUG）和 `--quiet`（WARNING）必须放在子命令之前，不能同时使用。
Quiet 隐藏成功确认，保留错误和显式请求的数据。格式化器使用
`LogRecord.getMessage()`，不移除 args，不修改 root logger，也不重复添加处理器。
OpenProxy 不记录响应体、请求体、头、query 或代理的原始错误详情；DEBUG 只记录
格式受限的规则 ID。访问日志已关闭。不会自动清除第三方库任意日志中的秘密信息。

## API 与统计

| GET | 用途 |
| --- | --- |
| /health | 名称、版本和 healthy 状态 |
| /api/v1/info | 应用能力 |
| /api/v1/config | 安全的配置视图 |
| /api/v1/proxy/status | enabled 与 running |
| /api/v1/proxy/stats | 当前进程的计数器 |
| /docs | OpenAPI 界面 |

计数器包括 active_connections、total_connections、mock_responses、
forwarded_requests、blocked_requests 和 errors。在同一事件循环中更新，更新过程
没有 await。Total 包含被拒绝的连接，active 包含 HTTP 和 CONNECT。Mock/block/
forward 统计已选择的动作，不保证响应已成功送达；errors 统计处理失败。不提供
字节计数。进程重启后统计归零，多个进程之间不共享统计。

## 诊断与故障排查

CLI 退出码：0 表示成功；1 表示服务器不可用、引擎异常或绑定失败；2 表示配置或
参数错误。Doctor 输出 PASS/WARN/FAIL。服务器未启动但端口空闲时为 WARN，退出码
为 0。运行中的 OpenProxy 不会被误判为端口冲突。启用代理后，status 还会通过 API
检查引擎状态；doctor 检查状态或代理端口是否可以绑定。检查不会预留端口，状态
可能在检查完成后立即变化。

- 403：没有允许请求的规则，或目标被策略禁止。
- 400：请求格式错误或分帧存在歧义。
- 502：连接失败或上游协议错误。
- 503：达到 max_connections 上限。
- 504：连接、读取或写入超时。
- 启动时端口错误：停止冲突进程或修改端口。

关闭时停止接受新连接，给活动任务 shutdown_timeout 时间完成，之后取消剩余
任务并关闭两侧传输。响应开始后发生错误时会关闭流，不再发送第二个 HTTP 响应。

## 检查与学习

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check src tests
uv run mypy
```

tests/test_proxy.py 使用真实的本地 HTTP/TCP 服务器和临时端口，覆盖流式传输、
方法、请求头、不访问上游的 mock、CONNECT、错误、安全策略和关闭流程。DNS 策略
另用替身测试，不访问外网。建议按 rules/models.py → rules/engine.py →
proxy/responses.py → proxy/server.py 的顺序阅读，再学习流式转发和 network.py。
原有 CLI/API/config/logging 测试均保留。

限制：不支持二进制文件 mock、keep-alive、持久化统计或规则编辑 UI。
Mock 响应体来自已加载到内存的 YAML，不适合超大型测试数据。没有速率限制，也不
限制一段时间内的请求总数。read_timeout 限制等待下一部分数据的时间；另有全局
request_timeout，默认 300 秒，同样适用于 CONNECT。长时间传输或隧道可将其增至
86400 秒。这是面向可信客户端的本地工具，不是加固的公共代理网关。

## 提交前检查

```bash
make check   # 锁文件、Ruff 检查与格式、mypy、pytest、YAML 示例
make build   # 在 dist/ 中构建 wheel 和源码分发包
```

不使用 make 时，可分别执行 Makefile 中的命令。使用 `make format` 自动格式化后，
再次运行 `make check`。`--locked` 防止检查期间静默更新依赖。工具缓存、构建产物
和本地 settings.yaml 均被 Git 忽略。

无需创建本地配置即可运行安全示例：

```bash
uv run openproxy start --config examples/mock.yaml
curl --noproxy '' --proxy http://127.0.0.1:8080 http://api.example.test/status
```

examples/mock.yaml 用于共享，秘密信息和个人设置应保存在本地 settings.yaml 中。

## v0.3.1 补丁版本

审计与回归测试说明见 [AUDIT-0.3.1.md](AUDIT-0.3.1.md)。

- 在 URL 规范化之前验证 Host 和 CONNECT authority，拒绝 userinfo、路径、query、
  fragment、带作用域的 IPv6、空端口和端口 0。Absolute-form 仍使用 URL authority；
  允许与之不同但格式正确的 Host。Origin-form 保留路径中的 `//`，拒绝错误的 DNS 名称。
- 入站及上游头最多 100 个字段，规范化后最多 16 KiB；h11 另限制未完成的头块。
  单个事件的解析 deadline 不会因每个 TCP 字节而延长，慢速头在 read_timeout 后超时。
- request_timeout 限制整个 HTTP exchange 或 CONNECT，默认 300 秒。错误或取消后
  释放连接槽。除 max_connections 外最多允许 16 个拒绝任务，更多连接直接重置，
  不返回 503。
- 逐跳头过滤同样处理 Proxy-Connection。
- allow_private_targets 为 false 时保守阻止 IPv6 site-local、NAT64、6to4 和 Teredo；
  IPv4-mapped IPv6 按内嵌 IPv4 校验。显式允许私有目标仍是仅供可信本地环境使用的
  策略放宽。
- Mock 拒绝非有限 JSON 数值、无效 UTF-8 文本及仅大小写不同的重复响应头；文本
  默认使用 charset=utf-8。
- 获取后台任务异常时不输出 traceback 或敏感详情，传输关闭停滞时执行 abort。

加强对错误请求的校验是有意的，合法的 v0.3.0 配置保持兼容。原有 HTTP/HTTPS
限制不变。这不是公共网关安全认证；API 和代理仍然没有身份认证。
