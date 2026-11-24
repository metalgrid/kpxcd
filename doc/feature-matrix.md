# kpxcd — Feature Matrix

## Database Management

| Feature | Status | Notes |
|---|---|---|
| KDBX 3.1 / 4 support | ✅ | Via gokeepasslib |
| Open multiple databases | ✅ | Database pool with concurrent access |
| Lock individual databases | ✅ | Via DBus / `kpxcctl lock <uuid>` |
| Lock all databases | ✅ | `kpxcctl lock all` |
| Idle timeout auto-lock | ✅ | Configurable `idle_timeout` |
| Screen lock integration | ❌ | `lock_on_screenlock` is parsed but not wired yet |
| File watcher (external edits) | ✅ | inotify; external changes trigger an in-memory reload with the retained credential |
| Atomic save with conflict detection | ✅ | Fingerprint-based optimistic locking |
| Adopt existing database as PAM default | ✅ | `kpxcctl adopt-default --replace <path>` |

## Auto-Unlock Methods

| Method | Status | Notes |
|---|---|---|
| PAM login (socket IPC + HKDF) | ✅ | Derives key from login password, sends over Unix socket. No plaintext on disk |
| `kpxcctl unlock` (PAM credential) | ✅ | Derives HKDF token from login password, unseals age identity locally |
| `kpxcctl unlock <path>` (password) | ✅ | Plain password prompt, works with any KDBX |
| systemd credential | ✅ | `LoadCredential=` in service unit |
| Secret Service | ✅ | PAM can bootstrap the default DB; Secret Service is a served API, not an unlock source |
| Keyfile | ✅ | Configured per-database |
| YubiKey challenge-response | 🚧 | Plumbing exists, but config validation does not enable it yet |
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
| Collection listing | ✅ | Unlocked databases are exposed as collections; collection create/delete is not supported |
| Item search by attributes | ✅ | Chrome, VS Code, `secret-tool` compatible |
| Encrypted session transport | ✅ | AES-CBC with DH key exchange per session |
| Item write-back | ✅ | Apps can create/update secrets |
| Polkit authorization gate | ✅ | Optional confirmation prompt before serving secrets; fails closed when enabled |
| Desktop notification on access | ✅ | "Chrome accessed a secret" |
| Access logging | ✅ | Caller PID, exe, app name |

## SSH Agent

| Feature | Status | Notes |
|---|---|---|
| Agent mode (kpxcd is the agent) | ✅ | Unix socket at `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` |
| Client/proxy mode | ✅ | Push keys into existing agent (e.g. ssh-agent, gnome-keyring) |
| Key extraction from KeePass | ✅ | KeeAgent XML metadata only; entries must set allowUseOfSshKey (addAtDatabaseOpen for auto-load) |
| RSA, Ed25519, ECDSA keys | ✅ | Standard OpenSSH key types |
| Sign inside `security.Do()` | ✅ | Private key material in secret scope |
| Remove keys on database lock | ✅ | Configurable `remove_on_lock` |
| Confirm before use | ❌ | `confirm_on_use` is parsed/stored but not enforced by the built-in agent |
| Key lifetime | ❌ | `lifetime` is parsed/stored but not enforced by the built-in agent |
| Auto-add on database unlock | 🚧 | Works globally, but currently ignores per-database `ssh_auto_add` |
| `kpxcctl setup-ssh` | ✅ | Writes user-level systemd/env config for `SSH_AUTH_SOCK` based on `ssh_mode` |

## FIDO2 / Passkeys

Implemented means source plus isolated regression evidence, not live compatibility
or certification. Current Chrome/Firefox, live UHID and host polkit security checks
are NOT RUN/awaiting approval. Earlier browser reports predate this candidate.
See [passkey limits](passkeys.md) and [conformance evidence](fido2-conformance.md).

| Feature | Status | Notes |
|---|---|---|
| CTAP2 registration (MakeCredential) | ✅ offline | ES256; exact RP user handle persisted; live browser test pending |
| CTAP2 assertion (GetAssertion) | ✅ offline | RP/type/ID-bound full allow list and discoverable selection |
| Multiple accounts / GetNextAssertion | ✅ offline | Channel-bound 30s continuation; revalidated on lock/reopen/replacement |
| Resident same-account replacement | ✅ offline | Explicit rk=true; selected destination only; multiple/cross-unlocked-DB matches refuse; hidden locked matches not inspected |
| Existing credentials | ✅ offline | No migration; unrelated KeePass fields retained; historical wrong handles generally need approved affected-only re-registration |
| GetInfo conformance | ✅ | versions, browser-generation algorithms (ES256 only), options, fixed product AAGUID, maxMsgSize; isolated regression evidence in fido2-conformance.md |
| User verification (UV) | ✅ offline | Independent of UP; actual verdicts, assuming shipped fresh auth_self policy; host security unverified |
| User presence | ✅ offline | Standard up default; silent assertion probes with up=false/uv=false bypass gate, not exclusions |
| excludeList enforcement | ✅ offline | RP/type/ID-bound disclosure only after required consent |
| Native authorization cancellation | ✅ offline | Same-connection polkit Cancel; bounded cleanup, no rollback of completed writes; single Unix bus address only |
| Fixed product AAGUID | ✅ | ab449b5e-d0bf-4d8d-81b1-de5ec1a8c00e; legacy override loads with a warning and is ignored |
| Bitwarden import | ✅ | base64url keys, UUID-shaped credential IDs, sign counter carried |
| clientPin | ❌ | UV is the gate instead; pinUvAuth protocols not implemented |
| credProtect / largeBlob / caBLE / hmac-secret | ❌ | Not implemented |
| D-Bus CreatePasskey / AssertPasskey | ✅ | Active local APIs; local random handle / caller hash, separate polkit path; CLI has no assert command |

## D-Bus API (`org.keepassxc.Daemon`)

| Method | Status | Notes |
|---|---|---|
| `ListDatabases` | ✅ | Returns UUID, name, path, locked state |
| `UnlockDatabase` | ✅ | Password and keyfile credentials; YubiKey config path is not enabled yet |
| `LockDatabase` | ✅ | By UUID |
| `LockAll` | ✅ | |
| `GetEntry` | ✅ | By UUID + entry path; returns safe metadata only |
| `SearchEntries` | ✅ | By UUID + query |
| `CreatePasskey` | ✅ | Local append-only ES256/EdDSA creation; not website registration |
| `AssertPasskey` | ✅ | Caller supplies hash; UP set after separate polkit gate, not native UV contract |
| `GetTotp` | ❌ | Returns "not yet implemented" |
| `GeneratePassword` / `GeneratePassphrase` | ❌ | Return "not yet implemented" |

## Security

| Feature | Status | Notes |
|---|---|---|
| `mlockall` (prevent swap) | 🚧 | Called at startup, but warns and continues if unavailable |
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
| Arch Linux package recipe | ✅ | PKGBUILD lives in `contrib/packaging/arch/`; generated makepkg artifacts stay ignored |
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
| FIDO2/passkey storage and signing | ✅ | KeePass-backed credentials, PKCS#8 keys, persisted counters |
| FIDO2 virtual CTAP2 device (browsers) | ✅ offline | Synthetic production-envelope/framing tests; current live kernel/browser checks pending |
| FIDO2 UV via gate | ✅ offline | Actual checks; fresh-auth policy assumption, not fake-test security proof |
| FIDO2 presence gate | ✅ offline | Interactive approval, silent assertion distinction; deny-by-default |
| Bitwarden passkey import | ✅ | `kpxcctl passkey import` on decrypted JSON exports (ECDSA P-256) |
| FIDO2 clientPin, credProtect, largeBlob, caBLE, hmac-secret | ❌ | Out of scope for v0.2 (see doc/threat-model.md) |
| Secret Service credential source | ❌ | Removed — circular dependency with kpxcd's own Secret Service server |
| `kpxcctl ssh list/add/remove` | ✅ | Wired to AgentServer IdentityManager |
| `kpxcctl ssh scan/show` | ✅ | Database scanning and key inspection |
| `kpxcctl ssh generate` | ✅ | In-place key generation with KeeAgent metadata |
| `kpxcctl ssh import/export` | ✅ | PEM key import/export with attachment handling |
| `kpxcctl ssh diag` | ✅ | Agent diagnostics |
| Database reload on file change | ✅ | Re-decodes with the retained credential; keeps previous content on failure |
