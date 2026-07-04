# kpxcd — KeePassXC Daemon for Linux

## What It Is

`kpxcd` is a headless user-session daemon that keeps one or more KeePass databases unlocked and available through standard Linux interprocess interfaces. It is written in Go, produces a single static binary, and runs as a systemd user service.

It exists because the KeePassXC GUI is the wrong tool for unattended or programmatic password access. Users who need SSH keys and passwords available throughout a login session — without keeping a GUI application running — need a daemon.

## Goal

**Provide continuous, secure, programmatic access to KeePass database contents for the duration of a user session on Linux.**

"Programmatic access" means: other programs on the same machine retrieve secrets from `kpxcd` through well-defined APIs — they do not parse `.kdbx` files themselves, and they do not require the KeePassXC GUI to be open.

## What It Does

| Capability | Interface | Mechanism |
|-------------|-----------|-----------|
| Unlock and hold databases in memory | DBus, CLI | `org.keepassxc.Daemon.UnlockDatabase` / `kpxcctl unlock` |
| Lock databases on demand or timeout | DBus, CLI | `org.keepassxc.Daemon.LockDatabase` / `kpxcctl lock` |
| Expose and persist passwords as freedesktop Secret Service | DBus | `org.freedesktop.secrets` — Secret Service clients can retrieve, create, and update items |
| Provide SSH keys to `ssh-agent` | Unix socket | SSH agent protocol server on `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` |
| FIDO2 / WebAuthn passkeys | DBus, CLI | Disabled; storage and assertions are still in progress |
| Search entries by URL, title, username | DBus, Secret Service | Attribute-based search |
| Auto-unlock databases at session start | systemd/PAM | Configured via `config.toml`; default DB can unlock from PAM login token |
| Re-lock on inactivity | DBus, systemd | Idle timer works; screen-lock listener is not implemented yet |

## What It Does Not Do

These are explicit non-goals. They belong to other tools.

| Non-goal | Reason | Alternative |
|----------|--------|-------------|
| **General-purpose database editing** | `kpxcd` supports narrow Secret Service item create/update operations for application compatibility, but it is not a full KeePass database manager. | `keepassxc-cli` |
| **Provide a GUI** | The purpose is headless operation. | KeePassXC |
| **Browser extension integration** | Browser integration requires a different IPC model and native messaging host. | KeePassXC browser proxy |
| **Auto-type** | Requires X11/Wayland window management. | KeePassXC |
| **KeeShare / database synchronization** | `kpxcd` only performs narrow Secret Service write-back; database merge/sync belongs elsewhere. | KeePassXC |
| **Windows or macOS support** | Operating system interfaces are fundamentally different. OS-specific secret managers already exist on those platforms. | Windows Credential Manager, macOS Keychain |
| **Full KeePass entry authoring** | `kpxcd` only writes entries created/updated through Secret Service compatibility paths. Advanced fields, attachments, history editing, and database management remain out of scope. | `keepassxc-cli add` |
| **Hardware FIDO2 token management** | `kpxcd` does not currently provide passkey operations and does not provision physical security keys. | `fido2-token`, `ykman` |
| **Network access** | `kpxcd` does not phone home, download icons, or check for updates. It opens local files and listens on local sockets only. | — |

## Scope Boundaries

### In Scope

- Reading KDBX 3.1 and KDBX 4.0 databases (all supported ciphers: AES-256, ChaCha20, Twofish)
- Key derivation: AES-KDF (KDBX 3.1), Argon2d, Argon2id (KDBX 4.0)
- Composite keys: password and keyfile; YubiKey challenge-response plumbing exists but is not enabled by config validation yet
- SSH agent protocol (OpenSSH agent protocol, Unix socket)
- Freedesktop Secret Service D-Bus specification v0.2
- WebAuthn / FIDO2 software authenticator plumbing is present but disabled until storage and assertion signing are complete
- systemd user service integration
- Polkit authorization for sensitive operations
- Secure memory handling (`runtime/secret`, best-effort `mlockall`)

### Out of Scope

- General-purpose KDBX editing beyond Secret Service item create/update operations
- Auto-type simulation
- Browser native messaging host
- Database merging or synchronization
- Hardware security key provisioning
- Network connectivity (fetching favicons, update checks)
- TOTP generation and password/passphrase generation until their D-Bus methods are implemented
- macOS, Windows, or BSD porting

## Security Model

### Threats Addressed

1. **Offline database theft** — The database file on disk is encrypted. `kpxcd` does not weaken KDBX encryption.
2. **Memory inspection by unprivileged processes** — Sensitive operations use `runtime/secret.Do()` where practical. Unprivileged processes cannot normally read `/proc/$pid/mem` (Linux default `kernel.yama.ptrace_scope ≥ 1`).
3. **Swap leakage** — `kpxcd` calls `mlockall`; if the system memlock limit prevents it, the daemon logs a warning and continues.
4. **Secret Service access by other session processes** — Secret Service intentionally follows the GNOME Keyring/libsecret model: same-user apps can access exposed, unlocked secrets. Set `require_confirmation = true` to require Polkit confirmation for secret reads.

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
| Keyfile on disk | Low — plaintext file, but can be on encrypted `/home` | Auto-unlock with encrypted home |
| Interactive prompt via `kpxcctl unlock` | High — password never touches disk | Manual unlock |
| Polkit-authorized DBus call | High — user must authenticate | Remote unlock |

YubiKey challenge-response plumbing exists but is not enabled by current config validation.

## Relationship to KeePassXC

`kpxcd` is a separate project. It shares no code with KeePassXC (C++/Qt). It interoperates with KeePassXC by:

1. **Reading the same `.kdbx` files** — both tools can open the same databases.
2. **Understanding KeePassXC entry metadata** — KeeAgent settings, browser integration attributes, passkey custom data.
3. **Running alongside KeePassXC** — both can have the same database open; `kpxcd` detects on-disk changes and refuses writes if the file changed since unlock or last save.
4. **Sharing the same config source** — `kpxcd` reads `~/.config/keepassxc/` for database MRU, last-used keyfiles, and display names.

`kpxcd` does **not**:
- Replace KeePassXC
- Share a process space with KeePassXC
- Need KeePassXC to be installed
- Write to KeePassXC's config
- Perform general-purpose KeePass database editing beyond Secret Service compatibility write-back

## Dependencies

### Runtime

- Linux kernel ≥ 5.4
- Go ≥ 1.26 (for `runtime/secret`, built with `GOEXPERIMENT=runtimesecret`)
- systemd ≥ 245 (for user service and `LoadCredential`)
- D-Bus session bus
- Polkit ≥ 0.120

### Libraries (Go modules)

| Library | Purpose | CGO? |
|---------|---------|------|
| `github.com/tobischo/gokeepasslib` | KDBX read/write | No |
| `github.com/godbus/dbus/v5` | D-Bus service | No |
| `golang.org/x/crypto` | SSH agent protocol, Argon2, ChaCha20, Salsa20, SSH key parsing | No |
| `golang.org/x/sys/unix` | `mlock`, `Munlock` | No |
| `github.com/fxamacker/cbor` | CBOR for FIDO2 passkeys | No |
| `github.com/pquerna/otp` | TOTP generation | No |
| `runtime/secret` (stdlib) | Secure memory erase | No (Go 1.26+) |

### Optional

- Rust toolchain + PAM headers — for `contrib/pam/kpxcd-pam`
- `libfido2` — for future hardware FIDO2 token support (out of scope for v1)

## Configuration

`kpxcd` reads `~/.config/kpxcd/config.toml`, creating it from embedded defaults on first run. See [`doc/config.md`](config.md) for the full specification.

## See Also

- [`doc/architecture.md`](architecture.md) — internal architecture and data flow
- [`doc/dbus-api.md`](dbus-api.md) — D-Bus interface specification
- [`doc/threat-model.md`](threat-model.md) — detailed threat model
- [`doc/config.md`](config.md) — configuration file reference