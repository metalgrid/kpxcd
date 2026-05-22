# kpxcd

A headless Linux daemon that keeps KeePass databases unlocked and available through standard system interfaces — Secret Service, SSH agent, and D-Bus — for the duration of a user session.

Written in Go. Single static binary. No Qt. No Botan. No CGO (except optional YubiKey PCSC support).

> **Status:** pre-1.0, Linux-only, security-sensitive software. Review the
> threat model and run it in a test user session before trusting it with
> production secrets.

## What It Does

- **Unlocks databases at session start** and holds them in memory
- **Secret Service** — exposes and persists secrets for any `org.freedesktop.secrets` client (`secret-tool`, Python `keyring`, browsers, `git-credential-libsecret`)
- **SSH agent** — serves OpenSSH keys stored in KeePass entries via the agent protocol
- **FIDO2 passkeys** — experimental credential creation plumbing (storage and assertions are still in progress)

## Planned / In Progress

- **TOTP** — time-based one-time-password generation
- **Password generation** — random passwords and passphrases

## What It Doesn't Do

- Act as a full database editor (Secret Service item writes are supported; general KeePass management still belongs in `keepassxc-cli` or a GUI)
- Provide a GUI
- Integrate with browsers (use the KeePassXC browser proxy)
- Auto-type
- Windows or macOS support
- Network access (no phone-home, no icon downloading)

## Quick Start

```bash
# Build (requires Go 1.26+ with GOEXPERIMENT=runtimesecret)
GOEXPERIMENT=runtimesecret make

# Run checks (includes the optional Rust PAM module)
make check

# Install
make install

# Start. On first run, kpxcd creates ~/.config/kpxcd/config.toml
# from its embedded defaults. The default config points to a local
# ~/.local/share/kpxcd/default.kdbx database and uses PAM auto-unlock
# when the optional PAM module is installed.
systemctl --user enable --now kpxcd

# Optional: edit the generated config to add existing databases.
$EDITOR ~/.config/kpxcd/config.toml

# Use
kpxcctl unlock /path/to/database.kdbx
kpxcctl list
kpxcctl get "example.com"
ssh-add -l  # should show keys from your database
secret-tool lookup kpxcd:dbname Default  # retrieve a password
```

## Documentation

| Document | Description |
|----------|-------------|
| [`doc/kpxcd.md`](doc/kpxcd.md) | Scope, goals, non-goals, security model |
| [`doc/architecture.md`](doc/architecture.md) | Internal architecture, data flow, concurrency model |
| [`doc/dbus-api.md`](doc/dbus-api.md) | D-Bus interface specification |
| [`doc/config.md`](doc/config.md) | Configuration file reference |
| [`doc/threat-model.md`](doc/threat-model.md) | Threat model and mitigations |
| [`doc/security-audit.md`](doc/security-audit.md) | Security review notes and mitigations |
| [`doc/feature-matrix.md`](doc/feature-matrix.md) | Implemented and planned feature status |

## Contributing and Security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development workflow and
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting.

## License

This repository contains mixed-license components:

- Go daemon and CLI code: MIT, see [`LICENSE`](LICENSE).
- Rust PAM module under [`contrib/pam/kpxcd-pam`](contrib/pam/kpxcd-pam): GPL-3.0-or-later, as declared in its `Cargo.toml`.

When distributing packages that include the PAM module, include the GPL-3.0-or-later license terms for that component.
