#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/local/.gen"
BIN="$GEN/bin"
LOG="$GEN/logs"
IDIR="${L7_IDENTITY_DIR:-/Users/kaka/Code/any/work/wt/roll-l7-identity}"
STUBDIR="${L7_STUB_DIR:-/Users/kaka/Code/any/work/wt/roll-l7-oauth-stub}"
DB="${L7_DATABASE_URL:-postgres://anywaye:anywaye@127.0.0.1:15500/identity?sslmode=disable}"

EDGE_PORT=19443
GW_PORT=19090
ID_PORT=19080
STUB_GOOGLE_PORT=19081
STUB_GITHUB_PORT=19082
REDIS_PORT=19579

names="anywaye.test api.anywaye.test auth.anywaye.test docs.anywaye.test localhost"

cmd="${1:-help}"

keygen() {
  mkdir -p "$GEN"
  printf 'basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
' > "$GEN/ca.ext"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=anywaye-local-ca" -keyout "$GEN/ca.key" -out "$GEN/ca.pem" -extfile "$GEN/ca.ext" 2>/dev/null
  san="$(printf 'DNS:%s,' $names | sed 's/,$//')"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=anywaye.test" \
    -keyout "$GEN/key.pem" -out "$GEN/req.csr" 2>/dev/null
  printf 'subjectAltName=%s\n' "$san" > "$GEN/san.ext"
  openssl x509 -req -days 825 -in "$GEN/req.csr" -CA "$GEN/ca.pem" -CAkey "$GEN/ca.key" \
    -CAcreateserial -extfile "$GEN/san.ext" -out "$GEN/cert.pem" 2>/dev/null
  rm -f "$GEN/req.csr" "$GEN/san.ext"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$GEN/oidc-signing.pem" 2>/dev/null
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$GEN/signup.key"; echo >> "$GEN/signup.key"
  head -c 32 /dev/urandom | base64 | tr -d '\n' > "$GEN/oauth-enc.key"; echo >> "$GEN/oauth-enc.key"
  chmod 600 "$GEN"/*.key "$GEN"/*.pem
  echo "keygen: CA + cert ($names) + OIDC RSA + two 32-byte keys in $GEN"
  openssl x509 -in "$GEN/cert.pem" -noout -subject -ext subjectAltName
}

build() {
  mkdir -p "$BIN" "$LOG"
  (cd "$IDIR" && mise exec -- go build -o "$BIN/identity" ./cmd/identity)
  (cd "$ROOT" && mise exec -- go build -o "$BIN/gateway" ./cmd/gateway)
  (cd "$ROOT" && mise exec -- go build -o "$BIN/edge" ./local)
  (cd "$STUBDIR" && mise exec -- go build -o "$BIN/oauth-stub" .)
  echo "build: identity gateway edge oauth-stub in $BIN"
}

migrate() {
  (cd "$IDIR" && mise exec -- goose -dir migrations postgres "$DB" up)
}

redis_up() {
  if docker ps --format '{{.Names}}' | grep -qx l7-redis; then return 0; fi
  docker rm -f l7-redis >/dev/null 2>&1 || true
  docker run -d --name l7-redis -p "127.0.0.1:$REDIS_PORT:6379" redis:7.4.1-alpine >/dev/null
  echo "redis: l7-redis on 127.0.0.1:$REDIS_PORT"
}

start_one() {
  name="$1"; bin="$2"; envf="$3"; log="$4"
  if [ -f "$GEN/$name.pid" ] && kill -0 "$(cat "$GEN/$name.pid")" 2>/dev/null; then
    echo "$name: already running (pid $(cat "$GEN/$name.pid"))"
    return 0
  fi
  (set -a; . "$envf"; set +a; nohup "$bin" >>"$log" 2>&1 < /dev/null & echo $! > "$GEN/$name.pid")
  echo "$name: started (pid $(cat "$GEN/$name.pid"))"
}

write_env() {
  google_id="local-anywaye-google-client"; google_secret="local-anywaye-google-secret"
  github_id="local-anywaye-github-client"; github_secret="local-anywaye-github-secret"

  printf 'OAUTH_STUB_ADDR=127.0.0.1:%s\nOAUTH_STUB_CLIENT_ID=%s\nOAUTH_STUB_CLIENT_SECRET=%s\nOAUTH_STUB_EMAIL_DOMAIN=anywaye.test\n' \
    "$STUB_GOOGLE_PORT" "$google_id" "$google_secret" > "$GEN/stub-google.env"
  printf 'OAUTH_STUB_ADDR=127.0.0.1:%s\nOAUTH_STUB_CLIENT_ID=%s\nOAUTH_STUB_CLIENT_SECRET=%s\nOAUTH_STUB_EMAIL_DOMAIN=anywaye.test\n' \
    "$STUB_GITHUB_PORT" "$github_id" "$github_secret" > "$GEN/stub-github.env"

  {
    echo "PORT=$ID_PORT"
    echo "LOG_LEVEL=info"
    echo "DATABASE_URL=$DB"
    echo "OIDC_ISSUER=https://auth.anywaye.test"
    echo "OIDC_SIGNING_KEY_ID=local-anywaye-test-1"
    echo "OIDC_LOGIN_UI_URL=https://anywaye.test/login"
    echo "SIGNUP_SIGNING_KEY=$(cat "$GEN/signup.key")"
    echo "OAUTH_ENCRYPTION_KEY=$(cat "$GEN/oauth-enc.key")"
    echo "OAUTH_REDIRECT_BASE_URL=https://auth.anywaye.test"
    echo "OAUTH_GOOGLE_CLIENT_ID=$google_id"
    echo "OAUTH_GOOGLE_CLIENT_SECRET=$google_secret"
    echo "OAUTH_GITHUB_CLIENT_ID=$github_id"
    echo "OAUTH_GITHUB_CLIENT_SECRET=$github_secret"
    echo "OAUTH_GOOGLE_AUTHORIZE_URL=http://localhost:$STUB_GOOGLE_PORT/google/authorize"
    echo "OAUTH_GOOGLE_TOKEN_URL=http://localhost:$STUB_GOOGLE_PORT/google/token"
    echo "OAUTH_GOOGLE_USERINFO_URL=http://localhost:$STUB_GOOGLE_PORT/google/userinfo"
    echo "OAUTH_GITHUB_AUTHORIZE_URL=http://localhost:$STUB_GITHUB_PORT/github/authorize"
    echo "OAUTH_GITHUB_TOKEN_URL=http://localhost:$STUB_GITHUB_PORT/github/access_token"
    echo "OAUTH_GITHUB_USERINFO_URL=http://localhost:$STUB_GITHUB_PORT/github/user"
    echo "OAUTH_GITHUB_EMAILS_URL=http://localhost:$STUB_GITHUB_PORT/github/user/emails"
  } > "$GEN/identity.env"
  printf '# OIDC_SIGNING_KEY is exported, exported by up from the PEM file, not the env file.\n' >> "$GEN/identity.env"

  {
    echo "PORT=$GW_PORT"
    echo "LOG_LEVEL=info"
    printf '%s\n' "ROUTE_TABLE='{\"/v1/auth/oauth\":{\"baseUrl\":\"http://127.0.0.1:$ID_PORT\",\"public\":true},\"/v1\":{\"baseUrl\":\"http://127.0.0.1:$ID_PORT\"}}'"
    printf '%s\n' "VHOST_TABLE='{\"auth.anywaye.test\":{\"baseUrl\":\"http://127.0.0.1:$ID_PORT\"}}'"
    echo "IDENTITY_ISSUER=https://auth.anywaye.test"
    echo "IDENTITY_JWKS_URL=http://127.0.0.1:$ID_PORT/.well-known/jwks.json"
    echo "IDENTITY_URL=http://127.0.0.1:$ID_PORT"
    echo "REDIS_URL=redis://127.0.0.1:$REDIS_PORT"
  } > "$GEN/gateway.env"
  echo "env: wrote $GEN/{stub-google,stub-github,identity,gateway}.env"
}

up() {
  [ -f "$GEN/ca.pem" ] || { echo "run keygen first"; exit 1; }
  [ -x "$BIN/identity" ] || { echo "run build first"; exit 1; }
  mkdir -p "$LOG"
  redis_up
  write_env
  start_one stub-google "$BIN/oauth-stub" "$GEN/stub-google.env" "$LOG/stub-google.log"
  start_one stub-github "$BIN/oauth-stub" "$GEN/stub-github.env" "$LOG/stub-github.log"
  # Multiline PEM cannot cross xargs: export it in this shell for identity only.
  OIDC_SIGNING_KEY="$(cat "$GEN/oidc-signing.pem")"
  export OIDC_SIGNING_KEY
  if [ -f "$GEN/identity.pid" ] && kill -0 "$(cat "$GEN/identity.pid")" 2>/dev/null; then
    echo "identity: already running"
  else
    (set -a; . "$GEN/identity.env"; set +a; OIDC_SIGNING_KEY="$OIDC_SIGNING_KEY" nohup "$BIN/identity" >>"$LOG/identity.log" 2>&1 < /dev/null & echo $! > "$GEN/identity.pid")
    echo "identity: started (pid $(cat "$GEN/identity.pid"))"
  fi
  unset OIDC_SIGNING_KEY
  start_one gateway "$BIN/gateway" "$GEN/gateway.env" "$LOG/gateway.log"
  if [ -f "$GEN/edge.pid" ] && kill -0 "$(cat "$GEN/edge.pid")" 2>/dev/null; then
    echo "edge: already running"
  else
    (nohup "$BIN/edge" -listen "127.0.0.1:$EDGE_PORT" -backend "http://127.0.0.1:$GW_PORT" \
      -cert "$GEN/cert.pem" -key "$GEN/key.pem" >>"$LOG/edge.log" 2>&1 < /dev/null & echo $! > "$GEN/edge.pid")
    echo "edge: started (pid $(cat "$GEN/edge.pid"))"
  fi
  wait_for
}

wait_for() {
  for i in $(seq 1 40); do
    if curl -sk --resolve "auth.anywaye.test:$EDGE_PORT:127.0.0.1" \
        "https://auth.anywaye.test:$EDGE_PORT/healthz" -o /dev/null 2>/dev/null; then
      echo "up: edge answers; gateway and identity behind it"
      return 0
    fi
    sleep 1
  done
  echo "up: edge never answered; logs in $LOG"; tail -5 "$LOG"/*.log 2>/dev/null; return 1
}

resolve_flags() {
  echo "--resolve $1:$EDGE_PORT:127.0.0.1 --cacert $GEN/ca.pem"
}

proofs() {
  echo "### (a) OIDC discovery through auth.anywaye.test"
  curl -s $(resolve_flags auth.anywaye.test) "https://auth.anywaye.test:$EDGE_PORT/.well-known/openid-configuration"
  echo; echo "### (b) JWKS"
  curl -s $(resolve_flags auth.anywaye.test) "https://auth.anywaye.test:$EDGE_PORT/.well-known/jwks.json"
  echo; echo "### (c) gateway readyz through api.anywaye.test"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" $(resolve_flags api.anywaye.test) "https://api.anywaye.test:$EDGE_PORT/readyz"
  curl -s $(resolve_flags api.anywaye.test) "https://api.anywaye.test:$EDGE_PORT/readyz"; echo
}

down() {
  for name in edge gateway identity stub-github stub-google; do
    if [ -f "$GEN/$name.pid" ]; then
      kill "$(cat "$GEN/$name.pid")" 2>/dev/null || true
      rm -f "$GEN/$name.pid"
      echo "$name: stopped"
    fi
  done
  docker rm -f l7-redis >/dev/null 2>&1 || true
  echo "down: loop stopped (keys and certs kept in $GEN)"
}

case "$cmd" in
  keygen|build|migrate|up|proofs|down) "$cmd" ;;
  *) echo "usage: local/run.sh {keygen|build|migrate|up|proofs|down}"; exit 1 ;;
esac
