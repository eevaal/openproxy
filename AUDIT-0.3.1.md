# OpenProxy v0.3.1 audit

Baseline: clean master, v0.3.0, 148 tests, Ruff/format/mypy passing.
Scope: HTTP/h11 framing, rules, DNS/SSRF, task ownership, admission/shutdown,
mock serialization, CLI/API/config and log privacy. No external test traffic.

## Confirmed findings and fixes

| Severity | Finding | Fix / regression |
| --- | --- | --- |
| High (availability) | Each header read renewed its timeout; a trickle could hold slots indefinitely. Streaming bodies and tunnels had no total deadline. | One event deadline plus configurable request_timeout; real slow-header and incomplete-body tests. |
| High (availability) | Rejected connections still created tasks without a bound, waiting on peer I/O outside active limit. | At most max_connections + 16 tasks; excess peers aborted synchronously. Rejection drain bounded and close in finally. |
| Medium | Host values containing path/fragment and CONNECT fragments were reinterpreted by urlsplit; port 0 fell back to 80. Missing Host on HTTP/1.0 could escape as StopIteration/RuntimeError. | Strict authority helper, explicit zero-port rejection, safe missing-host handling; raw socket regressions before upstream dispatch. |
| Medium | Complete header blocks/count were not explicitly bounded (h11 limit covers incomplete blocks). | Normalized 16 KiB / 100-field checks on request and response events. |
| Medium | Proxy-Connection nominated headers were not stripped. | Filter both connection header variants. |
| Medium | Invalid plain-text surrogate failed only at response encoding; non-finite JSON emitted NaN/Infinity. Header keys differing only in case could contradict each other. | Validate text encoding, finite JSON and case-insensitive header uniqueness at config load. |
| Low | close timeout did not abort transport; unexpected task exceptions were not retrieved. | Abort timed-out close; done callback retrieves exceptions and logs only a constant message. |

## Defensive policy tightening (not a reproduced network exploit)

Default IP classification did not explicitly exclude IPv6 translation/transition
addresses that can encode an internal IPv4 target. IPv6 site-local (fec0::/10), NAT64 well-known/local-use,
6to4 and Teredo are now rejected under the default policy; IPv4-mapped IPv6 is
checked using the embedded address. Tests stub DNS and assert no connection call.
An actual SSRF through an enabled translation route was not attempted/reproduced.
All DNS answers must pass; connect still uses a numeric checked IP, never the
original hostname. Local private-target opt-in remains explicit.

## Reviewed invariants

- h11 rejects conflicting lengths; CL+TE explicitly rejected before forwarding.
- Malformed chunked bodies rejected during streaming; a forward connection may
  already exist before a later body framing error. Buffering entire bodies to
  validate them before connecting would violate the streaming requirement.
- Mock and block never call connect/DNS, including malformed bodies.
- Absolute-form authority remains authoritative; mismatch with a syntactically
  valid Host is allowed and Host is reconstructed for the upstream.
- Path matching stays encoded and exact; query subset semantics, priority and
  declaration-order tie breaking stay unchanged. Host validation now rejects
  malformed names instead of treating them as unmatched names.
- CONNECT rejects HTTP bodies and authority ambiguity; allowlist applies to the
  validated numeric port. TLS payload is opaque. Existing half-close tests pass.
- Truncated upstream response closes the stream without a second HTTP status.
  No successful response-splitting exploit was reproduced; regression retained.
- Concurrent counters use no await during increments. Status becomes false as
  soon as shutdown starts. API safe projection excludes rules/body/credentials.
- Client disconnect during upload/download closes upstream and frees tasks;
  shutdown cancels delayed mocks. Existing streaming/CONNECT tests remain.
- LogRecord.getMessage remains intact; request bodies, credentials and query
  are not logged by OpenProxy. Formatters do not sanitize arbitrary library text.

## Tests and remaining limits

New local regression suite: tests/test_hardening.py; deterministic 32-case seeded
request-target fuzz smoke test, without extra dependencies or internet.
Final validation: 200 pytest cases passed (148 original + 52 new), and targeted
hardening/proxy suite: 104 passed. Ruff lint, format check, strict mypy (29 files),
lock consistency, example YAML validation and git diff --check passed. Wheel and
source distribution for 0.3.1 built successfully. One pre-existing Starlette
TestClient deprecation warning remains. No new dependencies were added.

Still a local trusted-client tool: no authentication, TLS termination/MITM,
HTTP/2, keep-alive or public-gateway rate limiting. Header limits count normalized
h11 fields, not exact wire bytes. Streaming has no byte quota but is bounded by
request_timeout/backpressure. Mock bodies are trusted local YAML resident in
memory. DNS thread-pool resolution may finish after coroutine timeout; executor
work is not forcibly killed. IP policy cannot infer custom public-to-private
routing/NAT; use network isolation/firewalls as an additional boundary.
The finite request deadline may terminate formerly unbounded long-lived tunnels;
configure request_timeout appropriately. API response schemas remain compatible.
