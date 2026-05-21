# kpxcd — Security Audit

**Date:** 2026-05-18  
**Scope:** `runtime/secret.Do()` and `mlock` coverage  
**Status:** Initial audit — critical gaps identified

## Summary

The current `kpxcd` code has partial `runtime/secret.Do()` coverage and very limited `mlock` coverage. `security.Do()` is used for some database credential setup, protected-entry unlock, database lock clearing, and SSH signing, but many sensitive flows occur on the regular Go heap outside `security.Do()`: KeePass decode/decryption, master password string copies, Secret Service password retrieval, FIDO2 passkey generation/assertion, SSH key extraction/parsing/storage, and session encryption keys. `mlock` is only applied to `security.SecureString` backing buffers; decrypted databases, gokeepasslib credentials, SSH signers/private keys, FIDO2 private keys, Secret Service passwords, and session keys all live in normal heap memory.

## Sensitive Data Flow Table

| Sensitive data | File:lines | `runtime/secret.Do()` | `mlock` | Gap |
|---|---|---|---|---|
| DBus unlock password | `dbusapi/dbusapi.go:99-113` | No | Partially | Original DBus string remains heap |
| systemd credential password | `daemon/daemon.go:218-230` | No | Partially | `os.ReadFile` buffer heap copy |
| Master password → gokeepasslib | `dbpool/pool.go:181-182,315-330` | Partially | No | `SecureString.Bytes()` returns heap copy |
| KeePass KDF/decryption | `dbpool/pool.go:185-187` | No | No | `Decode(db)` outside `Do()` |
| Decrypted DB content | `dbpool/pool.go:185-217` | No | No | `db.Content` is ordinary heap |
| Protected entry unlock | `dbpool/pool.go:190-196` | **Yes** | No | Unprotected values remain in heap |
| DB lock clearing | `dbpool/pool.go:242-244` | **Yes** | No | Only nils Content; no recursive zeroing |
| SSH key in KeePass attribute | `sshagent/keeagent.go:111-114` | No | No | Heap string → []byte conversion |
| SSH key attachment bytes | `sshagent/keeagent.go:191-224` | No | No | Uses binary.Content heap directly |
| SSH key parsing | `sshagent/key.go:104-126` | No | No | `ssh.Signer` persists in heap |
| SSH signing via agent | `sshagent/server.go:214-225` | **Yes** | No | Signing in `Do()`, key storage not protected |
| FIDO2 passkey generation | `fido2/service.go:97-145` | No | No | Private key structs, DER, PEM all heap |
| FIDO2 assertion | `fido2/service.go:160-194,361-378` | No | No | Signing not in `Do()` |
| FIDO2 private key storage | `fido2/service.go:55,142` | No | No | `PrivateKeyPEM string` on heap |
| Secret Service password | `secretservice/item.go:105-144` | No | No | `GetPassword()` string on heap |
| Secret Service session key | `secretservice/session.go:37-44` | No | No | AES key on heap |
| Secret Service plaintext buffer | `secretservice/session.go:64-103` | No | No | Plaintext, padded copy, ciphertext heap |

## Critical Gaps

1. **Database decryption outside `security.Do()`** — `dbpool/pool.go:185-187`  
   The actual KDF and decryption happen in `gokeepasslib.NewDecoder(f).Decode(db)` outside `security.Do()`. Master key derivation and database decryption are the most sensitive operations.

2. **Decrypted database content not mlock'd** — `dbpool/pool.go:185-217`  
   `gokeepasslib.Database.Content` is an ordinary Go heap object. All passwords, notes, and custom data live in unprotected memory.

3. **SSH private keys held in heap** — `sshagent/key.go:104-126`, `sshagent/manager.go:36-37`  
   Parsed `ssh.Signer` objects persist in heap memory for the entire time a key is loaded.

4. **Secret Service passwords in heap** — `secretservice/item.go:105-144`  
   Password retrieval and encryption happen outside `security.Do()` without mlock.

5. **FIDO2 private keys in heap** — `fido2/service.go:97-145,160-194`  
   Both generation and assertion paths lack `security.Do()` and mlock protection.

## Recommended Fixes

### Immediate (v0.1)

1. **Call `security.MlockAll()` at daemon startup** — `daemon/daemon.go`  
   This prevents all current and future heap pages from being swapped. It's a blunt instrument but immediately addresses the mlock gap for all sensitive data including gokeepasslib internals.

2. **Wrap database decryption in `security.Do()`** — `dbpool/pool.go`  
   Move `buildCredentials()` and `Decode(db)` into a single `security.Do()` closure.

3. **Wrap Secret Service password retrieval in `security.Do()`** — `secretservice/item.go`  
   Wrap `GetPassword()` and encryption in `security.Do()`, wipe plaintext after.

4. **Wrap FIDO2 key generation and assertion in `security.Do()`** — `fido2/service.go`  
   Both `CreatePasskey()` and `AssertPasskey()` should run their crypto inside `security.Do()`.

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
