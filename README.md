# kpxcd

A headless Linux daemon that keeps KeePass databases unlocked and available through standard system interfaces — Secret Service, SSH agent, and D-Bus — for the duration of a user session.

Written in Go. Single static binary. No Qt. No Botan. No CGO (except optional YubiKey PCSC support).

## What It Does

- **Unlocks databases at session start** and holds them in memory
- **Secret Service** — exposes and persists secrets for any `org.freedesktop.secrets` client (`secret-tool`, Python `keyring`, browsers, `git-credential-libsecret`)
- **SSH agent** — serves OpenSSH keys stored in KeePass entries via the agent protocol
- **FIDO2 passkeys** — creates and asserts WebAuthn credentials stored in the database
- **TOTP** — generates time-based one-time passwords
- **Password generation** — generates random passwords and passphrases

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

# Install
make install

# Configure
mkdir -p ~/.config/kpxcd
cp doc/kpxcd.toml.example ~/.config/kpxcd/kpxcd.toml
# Edit the config to point to your database

# Store your password as a systemd credential
echo -n 'your-password' > ~/.local/share/kpxcd/personal.pass
chmod 600 ~/.local/share/kpxcd/personal.pass

# Start
systemctl --user enable --now kpxcd

# Use
kpxcctl unlock /path/to/database.kdbx
kpxcctl list
kpxcctl get "example.com"
ssh-add -l  # should show keys from your database
secret-tool lookup kpxcd:dbname Personal  # retrieve a password
```

## Documentation

| Document | Description |
|----------|-------------|
| [`doc/kpxcd.md`](doc/kpxcd.md) | Scope, goals, non-goals, security model |
| [`doc/architecture.md`](doc/architecture.md) | Internal architecture, data flow, concurrency model |
| [`doc/dbus-api.md`](doc/dbus-api.md) | D-Bus interface specification |
| [`doc/config.md`](doc/config.md) | Configuration file reference |
| [`doc/threat-model.md`](doc/threat-model.md) | Threat model and mitigations |

## License

GPL-3.0-or-later