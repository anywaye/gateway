# REPORT-local-gateway-redis-m121

m121: gateway's skipped live Redis tier, executed against the local launch stack.

## Result: PROOF WORKS — 14 passed, 0 failed, 0 skipped

## Revision

- gateway `8a7b47c` (branch `worker/m121-gateway-live-redis`)
- go1.26.1 darwin/arm64 (matches mise.toml pin 1.26.1)

## Stack health at run time

- `site-launch-redis-1`: `Up 7 minutes (healthy)`, published on host port 15800.
  Uptime and healthy status observed via read-only `docker ps` immediately
  before the run; the stack was stable, not mid-restart, so the run proceeded.
- No explicit manager "stack healthy" message arrived in this worker session;
  the observable state (healthy, 7 min uptime, whole `site-launch-*` stack
  `Up 7-8 minutes`) was taken as the health signal. If m120 restarts the
  stack again after this run, this proof covers the stack as it stood.
- Auth: none. The site compose (`site/caf.dev.compose.yaml`) defines the
  launch Redis as plain `redis:7-alpine` with no password, and gateway's
  `parseRedisURL` accepts only `redis://host:port` (no userinfo/password
  is ever sent — `internal/ratelimit/redis.go:560-596`). DSN built without
  secrets; nothing to redact.

## Command (documented CI procedure, local port)

Per `.github/workflows/ci.yml` `redis` job: derive the `-run` selector from
`^func Test` names in `internal/ratelimit/live_test.go` (excluding `TestMain`),
then run exactly once under `timeout 300` with the required flag set:

```
GATEWAY_REDIS_URL=<launch Redis, host port 15800> GATEWAY_REDIS_REQUIRED=1 \
  go test -count=1 -v -run "^(<14 names read from live_test.go>)$" ./internal/ratelimit/
```

- 14 names declared in `live_test.go` (15 `func Test*` minus `TestMain`).
- Output and exit captured to `/tmp/gate-m121-gateway-live-redis.log` (`.exit`).
- Redis was only spoken to by the tests through `Connect`, the transport
  production uses; per-run `live-<token>` key namespace with cleanup, so no
  other database content touched. No start/stop/flush/reconfigure of Redis.

## Totals

- `live tests declared in internal/ratelimit/live_test.go: 14`
- `passed=14 failed=0 skipped=0` (counted from `^--- PASS:` / `^--- FAIL:` /
  `^--- SKIP:` lines in the captured log)
- CI floor (`passed >= 14`, `skipped == 0`) met.
- Exit: `0` (from the captured `.exit` file, i.e. `go test`'s own status
  under `timeout 300`, not the pipe's).
- Elapsed: package time `0.836s`; wall clock under one 45s poll window
  (run finished before the first status poll returned).

## Failures / skips

- None. In particular `TestABurstFiredAtOnceAdmitsExactlyTheLimit`
  (512 concurrent, exactly 128 admitted) and
  `TestTheScriptAndTheMemoryStoreAgreeAcrossRandomisedLimits` (400
  randomised cases) both passed against the launch Redis.

## Notes for the manager

- This closes the m118 gap (13 live tests skipped, `GATEWAY_REDIS_URL` unset)
  for the launch stack as it stood at run time. It does not replace the
  `redis` CI job, which forces the tier on every run.
- Test-only packet: no product code changed, no full `bin/prime` rerun, no
  publish/deploy. Only this report is committed. Not pushed.
