# kpxcd — KeePassXC Daemon for Linux

## What It Is

`kpxcd` is a headless user-session daemon that keeps one or more KeePass databases unlocked and available through standard Linux interprocess interfaces. It is written in Go, produces a single static binary, and runs as a systemd user service.

It exists because the KeePassXC GUI is the wrong tool for unattended or programmatic password access. Users who need SSH keys, passwords, or passkeys available throughout a login session — without keeping a GUI application running — need a daemon.

## Goal

**Provide continuous, secure, programmatic access to KeePass database contents for the duration of a user session on Linux.**

"Programmatic access" means: other programs on the same machine retrieve secrets from `kpxcd` through well-defined APIs — they do not parse `.kdbx` files themselves, and they do not require the KeePassXC GUI to be open.

## What It Does

| Capability | Interface | Mechanism |
|-------------|-----------|-----------|
| Unlock and hold databases in memory | DBus, CLI | `org.keepassxc.Daemon.UnlockDatabase` / `kpxcctl unlock` |
| Lock databases on demand or timeout | DBus, CLI | `org.keepassxc.Daemon.LockDatabase` / `kpxcctl lock` |
| Expose passwords as freedesktop Secret Service | DBus | `org.freedesktop.secrets` — any Secret Service client can retrieve passwords |
| Provide SSH keys to `ssh-agent` | Unix socket | SSH agent protocol server on `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` |
| Create and assert FIDO2 / WebAuthn passkeys | DBus, CLI | `org.keepassxc.Daemon.CreatePasskey` / `AssertPasskey` |
| Generate TOTP codes | DBus, CLI | `org.keepassxc.Daemon.GetTotp` / `kpxcctl totp <entry>` |
| Search entries by URL, title, username | DBus, Secret Service | Attribute-based search |
| Auto-unlock databases at session start | systemd | Configured via `kpxcd.toml` |
| Re-lock on screen lock or inactivity | DBus, systemd | Listen to `org.freedesktop.ScreenSaver` and idle timers |

## What It Does Not Do

These are explicit non-goals. They belong to other tools.

| Non-goal | Reason | Alternative |
|----------|--------|-------------|
| **Edit or create databases** | `kpxcd` is a consumer, not a manager. Use `keepassxc-cli` or the KeePassXC GUI. | `keepassxc-cli` |
| **Provide a GUI** | The purpose is headless operation. | KeePassXC |
| **Browser extension integration** | Browser integration requires a different IPC model and native messaging host. | KeePassXC browser proxy |
| **Auto-type** | Requires X11/Wayland window management. | KeePassXC |
| **KeeShare / database synchronization** | Synchronization is a write operation. `kpxcd` does not modify databases. | KeePassXC |
| **Windows or macOS support** | Operating system interfaces are fundamentally different. OS-specific secret managers already exist on those platforms. | Windows Credential Manager, macOS Keychain |
| **Encrypt or create new entries** | `kpxcd` reads. It does not write to the database. | `keepassxc-cli add` |
| **Hardware FIDO2 token management** | `kpxcd` stores and uses software passkeys from the database. It does not provision or manage physical security keys. | `fido2-token`, `ykman` |
| **Network access** | `kpxcd` does not phone home, download icons, or check for updates. It opens local files and listens on local sockets only. | — |

## Scope Boundaries

### In Scope

- Reading KDBX 3.1 and KDBX 4.0 databases (all supported ciphers: AES-256, ChaCha20, Twofish)
- Key derivation: AES-KDF (KDBX 3.1), Argon2d, Argon2id (KDBX 4.0)
- Composite keys: password, keyfile, YubiKey challenge-response (via PCSC)
- SSH agent protocol (OpenSSH agent protocol, Unix socket)
- Freedesktop Secret Service D-Bus specification v0.2
- WebAuthn / FIDO2 software authenticator (credential creation and assertion using keys stored in the database)
- TOTP generation (RFC 6238, HMAC-SHA1/SHA256/SHA512)
- Password and passphrase generation
- systemd user service integration
- Polkit authorization for sensitive operations
- Secure memory handling (`runtime/secret`, `mlock`)

### Out of Scope

- KDBX write operations (creating, editing, or saving databases)
- Auto-type simulation
- Browser native messaging host
- Database merging or synchronization
- Hardware security key provisioning
- Network connectivity (fetching favicons, update checks)
- macOS, Windows, or BSD porting

## Security Model

### Threats Addressed

1. **Offline database theft** — The database file on disk is encrypted. `kpxcd` does not weaken KDBX encryption.
2. **Memory inspection by unprivileged processes** — Master keys and decrypted content are held in `mlock`ed pages and processed inside `runtime/secret.Do()` blocks. Unprivileged processes cannot read `/proc/$pid/mem` (Linux default `kernel.yama.ptrace_scope ≥ 1`).
3. **Swap leakage** — All pages containing key material are `mlock`ed, preventing write to swap partitions.
4. **DBus abuse by other session processes** — Sensitive operations (explicit password retrieval, key removal, database lock/unlock) require Polkit authorization.

### Threats Not Addressed

1. **Root compromise** — If an attacker has root, all bets are off. `mlock` does not protect against `ptrace` from root.
2. **Compromised KeePassXC instance** — If the KeePassXC GUI is also running and modifies the database file, `kpxcd` will detect the change via file watcher and re-read the database. It does not handle concurrent write access.
3. **Side-channel attacks** — Constant-time comparison is used for password checking, but `kpxcd` does not defend against cache timing or speculative execution attacks beyond what Go's runtime provides.
4. **Cold boot attacks** — `mlock` prevents swap-out, but does not prevent a physically present attacker from reading DRAM. Hibernation should be configured to encrypt the suspend image (`PMUtils` or `systemd-hibernate` with LUKS).

### Credential Sources

`kpxcd` can obtain the database unlock password from:

| Source | Security | Use Case |
|--------|----------|----------|
| systemd credential (`LoadCredential=`) | Medium — readable by the user's systemd instance | Auto-unlock at login |
| libsecret / Secret Service | Medium — requires another secret service to already be running | Auto-unlock if gnome-keyring or kwallet is available |
| Keyfile on disk | Low — plaintext file, but can be on encrypted `/home` | Auto-unlock with encrypted home |
| Interactive prompt via `kpxcctl unlock` | High — password never touches disk | Manual unlock |
| YubiKey challenge-response | High — requires physical token | High-security setups |
| Polkit-authorized DBus call | High — user must authenticate | Remote unlock |

## Relationship to KeePassXC

`kpxcd` is a separate project. It shares no code with KeePassXC (C++/Qt). It interoperates with KeePassXC by:

1. **Reading the same `.kdbx` files** — both tools can open the same databases.
2. **Understanding KeePassXC entry metadata** — KeeAgent settings, browser integration attributes, passkey custom data.
3. **Running alongside KeePassXC** — both can have the same database open simultaneously (read-only from `kpxcd`).
4. **Sharing the same config source** — `kpxcd` reads `~/.config/keepassxc/` for database MRU, last-used keyfiles, and display names.

`kpxcd` does **not**:
- Replace KeePassXC
- Share a process space with KeePassXC
- Need KeePassXC to be installed
- Write to KeePassXC's config or databases

## Dependencies

### Runtime

- Linux kernel ≥ 5.4 (for `mlock2` and `runtime/secret` support)
- Go ≥ 1.26 (for `runtime/secret`, built with `GOEXPERIMENT=runtimesecret`)
- systemd ≥ 245 (for user service and `LoadCredential`)
- D-Bus session bus
- Polkit ≥ 0.120

### Libraries (Go modules)

| Library | Purpose | CGO? |
|---------|---------|------|
| `github.com/tobischo/gokeepasslib` | KDBX read | No |
| `github.com/godbus/dbus/v5` | D-Bus service | No |
| `golang.org/x/crypto` | SSH agent protocol, Argon2, ChaCha20, Salsa20, SSH key parsing | No |
| `golang.org/x/sys/unix` | `mlock`, `Munlock` | No |
| `github.com/fxamacker/cbor` | CBOR for FIDO2 passkeys | No |
| `github.com/pquerna/otp` | TOTP generation | No |
| `runtime/secret` (stdlib) | Secure memory erase | No (Go 1.26+) |
| `github.com/ebfe/scard` | YubiKey PCSC (optional) | Yes (CGO to `libpcsclite`) |

### Optional

- `libpcsclite` — for YubiKey challenge-response unlock (requires CGO)
- `libfido2` — for hardware FIDO2 token support (requires CGO; out of scope for v1)

## Configuration

`kpxcd` reads `~/.config/kpxcd/kpxcd.toml`. See [`doc/config.md`](config.md) for the full specification.

## See Also

- [`doc/architecture.md`](architecture.md) — internal architecture and data flow
- [`doc/dbus-api.md`](dbus-api.md) — D-Bus interface specification
- [`doc/threat-model.md`](threat-model.md) — detailed threat model
- [`doc/config.md`](config.md) — configuration file reference