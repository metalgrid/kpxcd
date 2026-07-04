# kpxcd — Security Audit

**Date:** 2026-05-18
**Scope:** `runtime/secret.Do()` and `mlock` coverage
**Status:** Living audit — some immediate mitigations landed, important gaps remain

## Summary

The current `kpxcd` code has partial `runtime/secret.Do()` coverage and best-effort process-wide `mlockall()`. `security.Do()` is used for database credential setup/decode, protected-entry unlock, database lock clearing, Secret Service retrieval, and SSH signing. Many values still pass through ordinary Go strings/heap objects: gokeepasslib database content, SSH signers/private keys, FIDO2 private keys, Secret Service session keys, and compatibility-layer plaintext buffers. If `mlockall()` fails because `LimitMEMLOCK` is too low, the daemon logs a warning and continues.

## Sensitive Data Flow Table

| Sensitive data | File:lines | `runtime/secret.Do()` | `mlock` | Gap |
|---|---|---|---|---|
| DBus unlock password | `dbusapi/dbusapi.go` | Partially | Process-wide if `mlockall` succeeds | Original D-Bus string remains heap |
| systemd credential password | `daemon/daemon.go` | Partially | Process-wide if `mlockall` succeeds | `os.ReadFile` buffer heap copy |
| Master password → gokeepasslib | `dbpool/pool.go` | Partially | Process-wide if `mlockall` succeeds | `SecureString.Bytes()` returns heap copy |
| KeePass KDF/decryption | `dbpool/pool.go` | **Yes** | Process-wide if `mlockall` succeeds | Decrypted content remains ordinary Go heap |
| Decrypted DB content | `dbpool/pool.go` | N/A | Process-wide if `mlockall` succeeds | `db.Content` is ordinary heap |
| Protected entry unlock | `dbpool/pool.go` | **Yes** | Process-wide if `mlockall` succeeds | Unprotected values remain in heap |
| DB lock clearing | `dbpool/wipe.go` | **Yes** | Process-wide if `mlockall` succeeds | Best-effort recursive wipe |
| SSH key attachment bytes | `sshagent/keeagent.go` | No | Process-wide if `mlockall` succeeds | Uses binary content heap directly |
| SSH key parsing/storage | `sshagent/key.go`, `sshagent/manager.go` | No | Process-wide if `mlockall` succeeds | `ssh.Signer` persists in heap |
| SSH signing via agent | `sshagent/server.go` | **Yes** | Process-wide if `mlockall` succeeds | Signing in `Do()`, key storage not protected |
| FIDO2 passkey generation | `fido2/service.go` | **Yes** | Process-wide if `mlockall` succeeds | PEM/private key strings still heap |
| FIDO2 assertion | `fido2/service.go` | No | Process-wide if `mlockall` succeeds | Signing incomplete |
| Secret Service password | `secretservice/item.go` | **Yes** | Process-wide if `mlockall` succeeds | Secret Service API still creates plaintext copies |
| Secret Service session key | `secretservice/session.go` | No | Process-wide if `mlockall` succeeds | AES key slice not individually wiped on close |

## Critical Gaps

1. **Decrypted database content is ordinary Go heap** — `dbpool/pool.go`
   `gokeepasslib.Database.Content` is an ordinary Go heap object. `mlockall()` prevents swap only when it succeeds; the daemon currently continues if it fails.

2. **SSH private keys held in heap** — `sshagent/key.go:104-126`, `sshagent/manager.go:36-37`
   Parsed `ssh.Signer` objects persist in heap memory for the entire time a key is loaded.

3. **Secret Service plaintext copies still exist** — `secretservice/item.go`, `secretservice/session.go`
   Retrieval is wrapped in `security.Do()`, but compatibility with the Secret Service API still creates plaintext byte/string copies.

4. **FIDO2 private keys in heap** — `fido2/service.go:97-145,160-194`
   Creation uses `security.Do()`, but persistent storage and assertion signing are incomplete and private key PEM strings live on the heap.

## Recommended Fixes

### Immediate (v0.1)

1. **Make `mlockall()` operational by default** — add `LimitMEMLOCK=infinity` (or a measured high limit) to the systemd unit.

2. **Reduce string copies of secrets** — add byte-slice/callback APIs where dependencies allow it, and wipe owned plaintext buffers.

3. **Keep Secret Service confirmation fail-closed** — when `require_confirmation = true`, unavailable Polkit or unknown caller metadata must deny access.

4. **Finish FIDO2 before recommending it** — persistent storage and assertion signing are incomplete.

### Medium-term (v0.2)

5. **Add `security.WithBytes()` helper** — `security/security.go`
   Callback-style accessor that allocates via `Alloc()`, defers `Wipe()`, and runs inside `Do()`.

6. **Store SSH keys encrypted at rest** — `sshagent/key.go`
   Retain encrypted key bytes in mlock'd memory; parse into `ssh.Signer` only during `Sign()` inside `security.Do()`.

7. **Wipe database content on lock** — `dbpool/pool.go`
   Recursively zero password strings and protected entry values before setting `Content = nil`.

8. **Session key storage** — `secretservice/session.go`
   Store AES session keys in `security.Alloc()` memory; wipe on `Close()`.

## Resolved Issues

### PAM token plaintext file (fixed 2026-05-21)

**Previously:** The PAM module (`pam_kpxcd.so`) wrote the user's raw Unix login password to `$XDG_RUNTIME_DIR/kpxcd/pam-token` as a plaintext file. The daemon polled for this file every 2 seconds, read it, and deleted it.

**Risk:** The raw password was written to the filesystem (tmpfs), exposing it to anyone with root access or a kernel/filesystem bug during the brief window before the daemon consumed it.

**Fix:** The PAM module now derives a 32-byte kpxcd-specific token via HKDF-SHA256 from the login password (salt = `"kpxcd-pam-v1"`) and sends it over a Unix domain socket (`$XDG_RUNTIME_DIR/kpxcd/pam.sock`) managed by `kpxcd.socket`. The raw password is never written to disk. Leaking the derived token does not reveal the user's Unix password.

| Property | Before | After |
|---|---|---|
| Password on filesystem | Yes (tmpfs, ephemeral) | **No** |
| Raw password exposed | Yes | **No** (HKDF-derived key) |
| Transport | File poll (2s interval) | Unix socket (immediate) |
| Password reuse risk | High | **None** |

Files changed: `internal/daemon/pamsocket.go`, `internal/daemon/pam.go`, `internal/daemon/daemon.go`, `internal/pamcred/pamcred.go`, `internal/xdg/xdg.go`, `contrib/pam/kpxcd-pam/src/lib.rs`, `contrib/systemd/kpxcd.socket`.

## Warnings

- `security_fallback.go:18-20` — When built without `GOEXPERIMENT=runtimesecret`, `security.Do()` is a no-op. All audit claims only hold for `linux && runtimesecret` builds.
- `security.go:68-74` — `NewSecureString(s string)` accepts a `string`, meaning the caller already has an immutable heap copy.
- `security.go:77-84` — `SecureString.Bytes()` returns an unlocked heap copy.
- `dbpool/pool.go:242-244` — Locking a database only nils `Content`; data remains until GC.
