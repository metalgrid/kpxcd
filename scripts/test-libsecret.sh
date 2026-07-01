#!/usr/bin/env bash
# Integration test for libsecret mutations against a sandboxed D-Bus session.
# Usage: ./scripts/test-libsecret.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

export GOEXPERIMENT=runtimesecret

echo "==> Building kpxcd..."
go build -o /tmp/kpxcd-integration ./cmd/kpxcd

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"; pkill -f kpxcd-integration 2>/dev/null || true' EXIT

DBPATH="$TMPDIR/test.kdbx"
PASS="testpass123"

echo "==> Creating test database..."
mkdir -p "$TMPDIR/credentials"
printf '%s' "$PASS" > "$TMPDIR/credentials/dbpass"
go run ./scripts/mktestdb/main.go -path "$DBPATH" -password "$PASS"

cat > "$TMPDIR/config.toml" <<EOF
[daemon]
log_level = "info"
log_to_journald = false
ssh_mode = "client"
idle_timeout = 0
lock_on_screenlock = false

[[database]]
name = "TestDB"
path = "$DBPATH"
default = true
auto_unlock = true
unlock_credential = "systemd-credential"
systemd_credential_name = "dbpass"

[secret_service]
enabled = true
notify_on_access = false
require_confirmation = false

[ssh_agent]
enabled = false

[fido2]
enabled = false
EOF

echo "==> Starting sandboxed D-Bus session with kpxcd..."
export TMPDIR

dbus-run-session -- bash -c '
  set -euo pipefail
  CREDENTIALS_DIRECTORY="$TMPDIR/credentials" /tmp/kpxcd-integration -config "$TMPDIR/config.toml" -q &
  KPXCD_PID=$!
  trap "kill $KPXCD_PID 2>/dev/null || true" EXIT

  echo "==> Waiting for org.freedesktop.secrets..."
  for i in $(seq 1 100); do
    if dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | grep -q org.freedesktop.secrets; then
      echo "==> Secret Service is up"
      break
    fi
    sleep 0.1
  done

  if ! dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | grep -q org.freedesktop.secrets; then
    echo "FAIL: Secret Service did not appear on the bus"
    exit 1
  fi

  echo "==> Testing store + lookup..."
  printf "mysecret" | secret-tool store --label="Test Item" application myapp key myvalue
  RESULT=$(secret-tool lookup application myapp key myvalue)
  if [ "$RESULT" != "mysecret" ]; then
    echo "FAIL: lookup returned ${RESULT:-<empty>}"
    exit 1
  fi
  echo "OK: create + lookup"

  echo "==> Testing update (replace)..."
  printf "newsecret" | secret-tool store --label="Test Item Updated" application myapp key myvalue
  RESULT=$(secret-tool lookup application myapp key myvalue)
  if [ "$RESULT" != "newsecret" ]; then
    echo "FAIL: update returned ${RESULT:-<empty>}"
    exit 1
  fi
  echo "OK: update"

  echo "==> Testing delete..."
  secret-tool clear application myapp key myvalue
  RESULT=$(secret-tool lookup application myapp key myvalue || true)
  if [ -n "$RESULT" ]; then
    echo "FAIL: clear did not remove secret (${RESULT})"
    exit 1
  fi
  echo "OK: delete"

  echo "==> PASS: libsecret mutation integration test"
'
