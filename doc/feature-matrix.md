# kpxcd — Feature Matrix

## Database Management

| Feature | Status | Notes |
|---|---|---|
| KDBX 3.1 / 4 support | ✅ | Via gokeepasslib |
| Open multiple databases | ✅ | Database pool with concurrent access |
| Lock individual databases | ✅ | Via DBus / `kpxcctl lock <uuid>` |
| Lock all databases | ✅ | `kpxcctl lock all` |
| Idle timeout auto-lock | ✅ | Configurable `idle_timeout` |
| Screen lock integration | ✅ | `lock_on_screenlock = true` |
| File watcher (external edits) | ✅ | 30s polling, detects KeePassXC GUI changes |
| Atomic save with conflict detection | ✅ | Fingerprint-based optimistic locking |
| Adopt existing database as PAM default | ✅ | `kpxcctl adopt-default --replace <path>` |

## Auto-Unlock Methods

| Method | Status | Notes |
|---|---|---|
| PAM login (socket IPC + HKDF) | ✅ | Derives key from login password, sends over Unix socket. No plaintext on disk |
| `kpxcctl unlock` (PAM credential) | ✅ | Derives HKDF token from login password, unseals age identity locally |
| `kpxcctl unlock <path>` (password) | ✅ | Plain password prompt, works with any KDBX |
| systemd credential | ✅ | `LoadCredential=` in service unit |
| Secret Service | 🚧 | Stub exists, not yet implemented |
| Keyfile | ✅ | Configured per-database |
| YubiKey challenge-response | ✅ | Via PCSC slot number |
| None (no password) | ✅ | Insecure but supported |

## PAM Auto-Unlock Architecture

| Component | Status | Notes |
|---|---|---|
| Rust PAM module (`pam_kpxcd.so`) | ✅ | HKDF-SHA256 derivation, socket IPC, zero-on-drop |
| systemd socket unit (`kpxcd.socket`) | ✅ | Pre-creates socket, queues connections before daemon starts |
| age X25519 identity (sealed) | ✅ | `default.identity.age` — sealed with HKDF-derived token via scrypt |
| Database credential (sealed) | ✅ | `default.cred.age` — random 32-byte password, sealed to age identity |
| Retry on PAM connect | ✅ | 5 retries with backoff (50ms–250ms) |
| Password change detection | ❌ | Changing login password breaks sealed identity; rewrap not yet implemented |

## Secret Service (`org.freedesktop.secrets`)

| Feature | Status | Notes |
|---|---|---|
| Collection management | ✅ | Create/delete/list collections |
| Item search by attributes | ✅ | Chrome, VS Code, `secret-tool` compatible |
| Encrypted session transport | ✅ | AES-CBC with DH key exchange per session |
| Item write-back | ✅ | Apps can create/update secrets |
| Polkit authorization gate | ✅ | Optional confirmation prompt before serving secrets |
| Desktop notification on access | ✅ | "Chrome accessed a secret" |
| Access logging | ✅ | Caller PID, exe, app name |

## SSH Agent

| Feature | Status | Notes |
|---|---|---|
| Agent mode (kpxcd is the agent) | ✅ | Unix socket at `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` |
| Client/proxy mode | ✅ | Push keys into existing agent (e.g. ssh-agent, gnome-keyring) |
| Key extraction from KeePass | ✅ | KeeAgent XML metadata, attachment heuristics |
| RSA, Ed25519, ECDSA keys | ✅ | Standard OpenSSH key types |
| Sign inside `security.Do()` | ✅ | Private key material in secret scope |
| Remove keys on database lock | ✅ | Configurable `remove_on_lock` |
| Confirm before use | ✅ | Configurable `confirm_on_use` |
| Key lifetime | ✅ | Configurable `lifetime` (seconds) |
| Auto-add on database unlock | ✅ | Configurable `ssh_auto_add` per database |
| `kpxcctl setup-ssh` | ✅ | Writes user-level systemd/env config for `SSH_AUTH_SOCK` based on `ssh_mode` |

## FIDO2 / Passkeys

| Feature | Status | Notes |
|---|---|---|
| Passkey creation | 🚧 | Creates credential material; database storage integration is not complete |
| Passkey assertion | ❌ | Assertion signing is not yet fully implemented |
| Configurable AAGUID | ✅ | Defaults to KeePassXC's AAGUID |
| ES256 / EdDSA algorithms | ✅ | `-7`, `-8` |
| User verification | ✅ | `preferred` / `required` / `discouraged` |

## D-Bus API (`org.keepassxc.Daemon`)

| Method | Status | Notes |
|---|---|---|
| `ListDatabases` | ✅ | Returns UUID, name, path, locked state |
| `UnlockDatabase` | ✅ | Password, keyfile, YubiKey credentials |
| `LockDatabase` | ✅ | By UUID |
| `LockAll` | ✅ | |
| `GetEntry` | ✅ | By UUID + entry path |
| `SearchEntries` | ✅ | By UUID + query |
| `CreatePasskey` | 🚧 | Creates credential material; persistent storage still incomplete |
| `AssertPasskey` | ❌ | Signing/extraction not yet fully implemented |
| `GetTotp` | ❌ | Returns "not yet implemented" |
| `GeneratePassword` / `GeneratePassphrase` | ❌ | Return "not yet implemented" |

## Security

| Feature | Status | Notes |
|---|---|---|
| `mlockall` (prevent swap) | ✅ | Warns gracefully if unavailable |
| `runtime/secret.Do()` | ✅ | Zeroes registers/stack after secret scopes |
| `security.SecureString` | ✅ | mlock'd backing buffer, wiped on destroy |
| `security.Alloc()` / `Wipe()` | ✅ | mlock'd byte slices with explicit zeroing |
| Memory wipe on PAM token use | ✅ | `security.Wipe()` after unsealing |
| PAM module zero-on-drop | ✅ | Rust `Drop` impl zeroes derived token |
| Polkit integration | ✅ | Optional confirmation for secret access |
| `GOEXPERIMENT=runtimesecret` | ✅ | Required at build time for full protection |
| Fallback (no runtimesecret) | ✅ | `security.Do()` becomes no-op, daemon still works |

## Build & Packaging

| Feature | Status | Notes |
|---|---|---|
| Makefile | ✅ | `make build install test check pam` |
| Arch Linux package recipe | 🚧 | Keep package build artifacts out of the source tree; publish PKGBUILD separately or under `contrib/packaging/` |
| Vendored dependencies | ✅ | Full `vendor/` for offline/reproducible builds |
| Go 1.26 + `GOEXPERIMENT=runtimesecret` | ✅ | Required for secret scope support |
| Rust PAM module | ✅ | Built with Cargo, installed as `pam_kpxcd.so` |
| Man pages | ✅ | `kpxcd(8)`, `kpxcctl(1)`, `kpxcd.toml(5)` |
| Shell completions | ✅ | Bash, Fish, Zsh |

## Not Yet Implemented

| Feature | Status | Notes |
|---|---|---|
| PAM password change rewrap | ❌ | Changing login password breaks sealed identity |
| TOTP generation | ❌ | D-Bus method currently returns "not yet implemented" |
| Password/passphrase generation | ❌ | D-Bus methods currently return "not yet implemented" |
| FIDO2 passkey storage and assertion signing | ❌ | Creation plumbing exists, but storage/extraction and signing are incomplete |
| Secret Service credential source | 🚧 | `unlock_credential = "secret-service"` stub exists |
| `kpxcctl ssh list` | ❌ | Returns "not yet implemented" |
| Database reload on file change | ❌ | Watcher detects changes but doesn't reload in-memory |
