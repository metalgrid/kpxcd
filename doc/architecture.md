# kpxcd — Architecture

## Process Model

```
┌─────────────────────────────────────────────────────────────┐
│                     User Session                             │
│                                                             │
│  systemd --user                                             │
│  └── kpxcd.service                                          │
│       ├── D-Bus session bus connection                       │
│       │    ├── org.keepassxc.Daemon                         │
│       │    └── org.freedesktop.secrets (if enabled)          │
│       │                                                     │
│       ├── SSH agent Unix socket                             │
│       │    └── $XDG_RUNTIME_DIR/kpxcd/ssh.sock              │
│       │                                                     │
│       └── Control socket (kpxcctl ↔ daemon)                 │
│            └── $XDG_RUNTIME_DIR/kpxcd/control.sock          │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ ssh      │  │ git      │  │ secret-  │  │ kpxcctl    │  │
│  │          │  │ credential│  │ tool     │  │            │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
│        │              │             │              │        │
│        └──────┬───────┘─────────────┘──────────────┘        │
│               │                                              │
│               ▼                                              │
│          kpxcd (single process, single-threaded event loop)  │
│               │                                              │
│               ▼                                              │
│         Database Pool (in-memory)                           │
│         ┌────────┐ ┌────────┐ ┌────────┐                   │
│         │ DB 1   │ │ DB 2   │ │ DB n   │                   │
│         └────────┘ └────────┘ └────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

`kpxcd` is a single-process daemon. It uses Go's event loop (goroutines + `net/http`-style socket polling) to serve multiple concurrent clients. There is no forking, no worker pool, no separate process for SSH vs. Secret Service.

## Component Layout

```
kpxcd/
├── cmd/
│   └── kpxcd/          # main() entry point
│   └── kpxcctl/        # CLI client
├── internal/
│   ├── daemon/         # DaemonApp — lifecycle, signal handling, systemd notify
│   ├── dbpool/         # DatabasePool — open, close, lock, unlock, lookup
│   ├── kdbx/           # KDBX thin wrapper over gokeepasslib + secure key derivation
│   ├── config/         # TOML config parsing
│   ├── security/       # runtime/secret + mlock helpers
│   ├── dbusapi/        # org.keepassxc.Daemon D-Bus interface
│   ├── secretservice/  # org.freedesktop.secrets D-Bus implementation
│   ├── sshagent/       # SSH agent protocol server
│   ├── fido2/          # FIDO2 / passkey service
│   ├── passutil/       # Password, TOTP, passphrase generation/lookup
│   └── polkit/         # Polkit authorization helpers
├── doc/                # Documentation
└── go.mod
```

## Data Flow

### Database Unlock

```
               kpxcctl unlock /path/to/db.kdbx
                       │
                       ▼
              ┌─────────────────┐
              │  DBus:           │
              │  UnlockDatabase  │
              │  (path, cred)    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐      runtime/secret.Do(func() {
              │  security.Do()  │◄────   key := deriveKey(cred)
              │                 │        db := gokeepasslib.Open(path, key)
              └────────┬────────┆        pool.Add(db)
                       │             })
                       ▼
              ┌─────────────────┐
              │  DatabasePool    │──── mlock(db data)
              │  .Add(db)       │
              └────────┬────────┘
                       │
              ┌────────┴────────────────────┐
              │                              │
              ▼                              ▼
      SSH Agent: add                Secret Service:
      entries with                  register
      KeeAgent settings             collection
```

### Secret Service Lookup

```
  secret-tool lookup "kpxcd:dbname" "Personal"
               │
               ▼
      ┌─────────────────┐
      │  D-Bus:          │
      │  org.freedesktop  │
      │  .secrets         │
      │  .SearchItems     │
      └────────┬─────────┘
               │
               ▼
      ┌─────────────────┐
      │  SecretService   │
      │  .searchItems()  │
      └────────┬─────────┘
               │
      ┌────────┴────────┐
      │                   │
      ▼                   ▼
  Polkit auth?      Find entries
  (if required)     matching attrs
      │                   │
      └─────────┬─────────┘
                │
                ▼
         Return secret via
         encrypted Session
         (D-Bus Secret Service
          protocol)
```

### SSH Authentication

```
  ssh user@host
       │
       ▼
  SSH client connects to
  $XDG_RUNTIME_DIR/kpxcd/ssh.sock
       │
       ▼
  ┌──────────────────────┐
  │  SSH Agent Protocol   │
  │  SSH_AGENTC_REQUEST_  │
  │  IDENTITIES            │
  └──────────┬────────────┘
             │
             ▼
  ┌──────────────────────┐
  │  SSH Agent Server     │
  │  .listIdentities()    │
  └──────────┬───────────┘
             │
             ▼
  Iterate pool databases
  for entries with KeeAgent
  settings → OpenSSHKey
             │
             ▼
  Return public keys → SSH client
  signs challenge with
  private key inside
  runtime/secret.Do()
```

## Secure Memory Discipline

All paths that touch decrypted database content or derived keys follow this pattern:

```go
func (p *DatabasePool) Unlock(path string, cred Credential) error {
    return security.Do(func() {
        compositeKey := deriveCompositeKey(cred)
        db := gokeepasslib.Open(path, compositeKey)
        // compositeKey and db content are on mlock'd pages,
        // inside runtime/secret.Do scope. Registers and stack
        // will be zeroed before Do returns.
        p.mu.Lock()
        p.databases[db.UUID] = db
        p.mu.Unlock()
    })
}
```

Rules:

1. **Master keys are always derived inside `runtime/secret.Do()`.**
2. **All `[]byte` holding decrypted data is `mlock`'d before writing.** The `security` package provides `security.Alloc(n int) []byte` that calls `unix.Mlock` and `security.Wipe(b []byte)` that zeros and unlocks.
3. **Entry passwords are only materialized inside `runtime/secret.Do()` when returning via DBus.** Secret Service uses the encrypted session protocol, so the plaintext password is never held outside a secret scope.
4. **SSH private keys are only held inside `runtime/secret.Do()` during signing operations.** The SSH agent server keeps public key fingerprints and encrypted private key blobs in memory; the private key is decrypted into a secret scope only during the signing operation.

## Concurrency Model

- The daemon runs a single `main()` goroutine that drives the D-Bus event loop.
- Database unlock operations are CPU-intensive (Argon2 KDF). They run in a separate goroutine pool (bounded by `GOMAXPROCS`) and post results back to the main loop via channels.
- SSH agent connections are served by a goroutine-per-connection model, but signing operations enter `runtime/secret.Do()` which is not goroutine-safe — the `security` package serializes secret scopes with a mutex.
- `DatabasePool` is protected by a `sync.RWMutex`. Read locks for entry lookups; write locks for open/close/lock/unlock.

## Error Handling and Recovery

- **Corrupt database file**: Log error, do not crash. The database remains locked; the user is notified.
- **D-Bus session bus disappears**: Attempt to reconnect with exponential backoff. If the bus is gone for >30s, log and exit. systemd will restart.
- **SSH agent socket error**: Close and re-listen. Existing SSH sessions using already-negotiated keys continue to work.
- **Argon2 KDF timeout**: If unlock takes >30s (configurable), abort and return error to caller.
- **OOM / mlock failure**: If `mlock` fails, log a warning and continue. The data is still in memory, just not swap-protected. Do not refuse to operate — this is a degradation, not a fatal error.

## File Watcher

`kpxcd` watches all open database files for external modifications (using `inotify` via `fsnotify`). If the file changes:

1. Save the current in-memory data as a snapshot.
2. Reload the file (keeping the existing key material; keys do not change on reload).
3. If reload fails, keep the old version in memory and log an error.
4. If keys fail (file was re-encrypted with a different key), lock the database and notify the user.

This allows KeePassXC GUI to modify the database while `kpxcd` has it open.