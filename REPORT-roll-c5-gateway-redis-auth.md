# REPORT-roll-c5-gateway-redis-auth.md

## The seam

`Connect` (`internal/ratelimit/redis.go`) dialled and returned a connection
whose only commands were `PING` and `EVAL`. There was no `AUTH` anywhere in the
file, and `parseRedisURL` extracted hostname, port and tls from the URL while
**discarding the userinfo** — so `redis://:s3cret@host:6379` became an
unauthenticated dial. Against the box's password-protected Redis every command
was answered `NOAUTH`, and the readiness probe reported `redis: unavailable`
forever. Fail-open kept traffic unthrottled (documented, untouched); the
visible wound was the Deployment never becoming Ready.

## The evidence (live box, from the brief)

- Pod `0/1 Running` for 5+ hours; 1977 `Readiness probe failed: HTTP probe
  failed with statuscode: 503`.
- `/readyz` body through a port-forward:
  `{"deps":{"identity":"ok","redis":"unavailable"}}`.
- Identity JWKS reachable (200) and `redis-cli -a <password from
  gateway-secrets> ping` → `PONG` from the gateway namespace — service and
  password both fine, client at fault.
- `grep -n "AUTH|password|Password()" internal/ratelimit/redis.go` → no matches.

## The fix (`internal/ratelimit/redis.go`)

1. `parseRedisURL` returns `username` + `password` alongside host/port/tls
   (percent-decoded by `net/url`). Empty user + password is kept exactly as
   kit writes it — it is NOT read as "no user".
2. `Connect` sends AUTH immediately after the dial, before handing the
   connection out, and reads the reply:
   - empty user → `AUTH <password>` (legacy, kit's spelling);
   - named user → `AUTH <user> <password>` (Redis 6+ ACL);
   - neither → no AUTH write at all (unauthenticated Redis stays supported).
   A refused AUTH closes the socket and returns
   `… refused the Redis password: authentication failed: …` — the operator's
   password being wrong, said in those terms at connect time, not on the first
   PING.
3. Redaction: new `redactRedisURL` (`redis://:pw@host` → `redis://…@host`),
   same shape as `redactUserinfo` in `internal/httpapi` (this file previously
   had no redaction convention because no error here ever quoted a
   credential). Applied to the dial error, the AUTH refusal, and all four
   `parseRedisURL` refusals — which previously interpolated the raw URL and
   would have logged a password on e.g. a bad port. Same treatment for the
   live tier's `GATEWAY_REDIS_URL` fatalf in `live_test.go`.
4. Unchanged: probe name (`redis`), `/healthz`, fail-open (`Limiter.Wrap`),
   path refusal (still a startup error, with or without userinfo), no client
   library (AUTH rides the existing `Do` transport).
5. README `REDIS_URL` row documents the two AUTH shapes.

## The controls and their verdicts

New file `internal/ratelimit/redis_auth_test.go`: a scripted in-test TCP
server (real dial, real RESP2, no `redis-server`) that is strict — anything
before a successful AUTH is answered `NOAUTH`.

| Check | Verdict |
|---|---|
| `AUTH <password>` first write after dial, kit's URL shape | GREEN |
| `AUTH <user> <password>` for a named user | GREEN |
| no AUTH when the URL carries no userinfo | GREEN |
| refused AUTH names authentication, message contains no secret | GREEN |
| parse table (tls, percent-encoding, empty user) + path refusal kept + redaction unit | GREEN |
| RED 1: AUTH write reverted (`if false && …`) → first check red | RED confirmed: `PING … (false, … NOAUTH Authentication required.)`, FAIL |
| RED 2: password URL, connection never sends AUTH → authenticated-connection check fails | RED confirmed: same run, Ping refused NOAUTH — the live-box failure reproduced |
| `bin/prime-go` (gofmt, build, vet, test, codegen currency) | GREEN, exit 0, 272 passed |

Note on the RED run: the reverted tree fails at the Ping assertion before
reaching the transcript assertion — the transcript check fires on a tree that
sends something-else-first rather than nothing-at-all. Both halves were
observed red across the revert experiment (NOAUTH failure) and green on the
restored tree.
