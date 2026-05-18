# kpxcd — Configuration Reference

`kpxcd` reads a single TOML configuration file at startup.

## File Location

| Precedence | Path |
|------------|------|
| Default | `~/.config/kpxcd/kpxcd.toml` |
| Override | `kpxcd --config <path>` |
| XDG | `$XDG_CONFIG_HOME/kpxcd/kpxcd.toml` (if `XDG_CONFIG_HOME` is set) |

## Full Example

```toml
# kpxcd.toml — KeePassXC Daemon Configuration

[daemon]
# Lock all databases after this many seconds of inactivity (0 = disabled)
idle_timeout = 900

# Lock databases when the screensaver activates
lock_on_screenlock = true

# Log level: "error", "warn", "info", "debug"
log_level = "info"

# Log to journald instead of stderr (useful when run as systemd service)
log_to_journald = true

# Path to the SSH agent socket (relative to $XDG_RUNTIME_DIR)
ssh_socket_path = "kpxcd/ssh.sock"

# Whether to act as SSH agent or proxy to existing $SSH_AUTH_SOCK
ssh_mode = "agent"  # "agent" | "proxy"

[[database]]
# Path to the .kdbx file (required)
path = "/home/user/Passwords.kdbx"

# Display name (optional, defaults to filename)
name = "Personal"

# Auto-unlock this database when the daemon starts
auto_unlock = true

# Credential source for auto-unlock
# "systemd-credential" — read from systemd LoadCredential
# "secret-service"     — look up in org.freedesktop.secrets
# "keyfile"            — read a keyfile from disk
# "prompt"             — do not auto-unlock; wait for kpxcctl unlock
# "none"               — database has no password (dangerous)
unlock_credential = "systemd-credential"

# systemd credential name (only used if unlock_credential = "systemd-credential")
systemd_credential_name = "kpxcd-personal"

# Keyfile path (only used if unlock_credential = "keyfile")
keyfile = ""

# YubiKey slot for challenge-response (0 = disabled)
yubikey_slot = 0

# Which group to expose via Secret Service (empty = all groups)
secret_service_expose_group = ""

# Whether to auto-add SSH keys from this database to the agent
ssh_auto_add = true

[[database]]
path = "/home/user/Work.kdbx"
name = "Work"
auto_unlock = true
unlock_credential = "secret-service"
secret_service_label = "kpxcd-work-db-password"
ssh_auto_add = false

[secret_service]
# Whether to expose the Secret Service interface on D-Bus
enabled = true

# Show a desktop notification when a secret is retrieved
notify_on_access = true

# Require Polkit confirmation before returning a secret
require_confirmation = false

# Confirmation timeout in seconds (0 = no timeout, must click)
confirmation_timeout = 30

[ssh_agent]
# Whether to enable the SSH agent interface
enabled = true

# Remove identities from the agent when their database is locked
remove_on_lock = true

# Confirm before each SSH authentication (ssh-add -c behavior)
confirm_on_use = false

# Lifetime constraint in seconds (0 = no constraint, key persists until removed)
lifetime = 0

# Security key provider for sk-ssh-* key types
security_key_provider = "internal"

[fido2]
# Whether to enable the FIDO2 / passkey DBus interface
enabled = true

# AAGUID to report in attestation objects
# (KeePassXC uses a fixed AAGUID for software authenticator)
aaguid = "f8a011f3-8c0a-4d15-8006-17111f9edc7d"

# Supported algorithms
# -7  = ES256 (ECDSA P-256 with SHA-256)
# -25 = ES256K (ECDSA secp256k1 with SHA-256)  
# -37 = PS256 (RSASSA-PSS with SHA-256)
# -8  = EdDSA (Ed25519)
algorithms = [-7, -8]

# Require user verification for passkey operations
user_verification = "preferred"  # "required" | "preferred" | "discouraged"
```

## Section Reference

### `[daemon]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `idle_timeout` | int | `0` | Seconds of inactivity before locking all databases. `0` disables. |
| `lock_on_screenlock` | bool | `true` | Lock databases when the screensaver activates. |
| `log_level` | string | `"info"` | Minimum log severity. |
| `log_to_journald` | bool | `false` | Log to systemd journal instead of stderr. |
| `ssh_socket_path` | string | `"kpxcd/ssh.sock"` | Path relative to `$XDG_RUNTIME_DIR` for the SSH agent socket. |
| `ssh_mode` | string | `"agent"` | `"agent"` = act as SSH agent; `"proxy"` = forward to existing `$SSH_AUTH_SOCK`. |

### `[[database]]`

This is a TOML array of tables — repeat the `[[database]]` header for each database.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | *required* | Absolute path to the `.kdbx` file. |
| `name` | string | filename | Human-readable name for the database. |
| `auto_unlock` | bool | `false` | Attempt to unlock this database when the daemon starts. |
| `unlock_credential` | string | `"prompt"` | How to obtain the password for auto-unlock. One of: `systemd-credential`, `secret-service`, `keyfile`, `prompt`, `none`. |
| `systemd_credential_name` | string | `""` | Name of the systemd credential holding the password. Only used when `unlock_credential = "systemd-credential"`. |
| `keyfile` | string | `""` | Path to a keyfile. Used when `unlock_credential = "keyfile"` or as a secondary factor. |
| `yubikey_slot` | int | `0` | YubiKey challenge-response slot. `0` = disabled, `1` or `2` = slot number. |
| `secret_service_expose_group` | string | `""` | UUID or name of a group to restrict Secret Service exposure to. Empty = expose all. |
| `ssh_auto_add` | bool | `true` | Automatically add SSH keys from entries with KeeAgent settings when the database is unlocked. |

### `[secret_service]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Expose `org.freedesktop.secrets` on the session bus. |
| `notify_on_access` | bool | `true` | Show a desktop notification when a secret is retrieved. |
| `require_confirmation` | bool | `false` | Require Polkit confirmation before returning any secret. |
| `confirmation_timeout` | int | `30` | Seconds before confirmation dialog times out and is denied. `0` = no timeout. |

### `[ssh_agent]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Listen on the SSH agent socket. |
| `remove_on_lock` | bool | `true` | Remove identities from the agent when their database is locked. |
| `confirm_on_use` | bool | `false` | Require user confirmation before each SSH authentication. |
| `lifetime` | int | `0` | Maximum lifetime for added identities in seconds. `0` = unlimited. |
| `security_key_provider` | string | `"internal"` | Security key provider for `sk-ssh-*` key types. `"internal"` = use built-in Go SSH implementation. |

### `[fido2]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable FIDO2 / passkey DBus methods. |
| `aaguid` | string | KeePassXC AAGUID | AAGUID reported in attestation objects. |
| `algorithms` | int[] | `[-7, -8]` | COSE algorithm IDs supported by the software authenticator. |
| `user_verification` | string | `"preferred"` | User verification requirement. |

## Path Expansion

All path fields in the config support shell-like variable expansion:

| Syntax | Expands To | Example |
|--------|-----------|--------|
| `~` | User's home directory | `~/Passwords.kdbx` → `/home/alice/Passwords.kdbx` |
| `$HOME` | HOME environment variable | `$HOME/Passwords.kdbx` → `/home/alice/Passwords.kdbx` |
| `${HOME}` | Same as above (brace syntax) | `${HOME}/Passwords.kdbx` |
| `$XDG_RUNTIME_DIR` | XDG runtime directory | `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` |
| `relative/path` | Resolved against `$XDG_CONFIG_HOME/kpxcd/` | `ssh.sock` → `/home/alice/.config/kpxcd/ssh.sock` |
| `/absolute/path` | Used as-is | `/home/alice/Passwords.kdbx` |

This means you can write:

```toml
path = "~/Passwords.kdbx"
# or
path = "$HOME/Passwords.kdbx"
# or
keyfile = "~/.config/kpxcd/keyfile.key"
```

systemd ≥ 250 supports `LoadCredential=` and `SetCredential=` in service units. The password is passed to `kpxcd` via a file descriptor:

```ini
# ~/.config/systemd/user/kpxcd.service
[Service]
LoadCredential=kpxcd-personal:/home/user/.local/share/kpxcd/personal.pass
```

`kpxcd` reads the password from `$CREDENTIALS_DIRECTORY/kpxcd-personal`.

The credential file should be readable only by the user:

```bash
echo -n 'my-password' > ~/.local/share/kpxcd/personal.pass
chmod 600 ~/.local/share/kpxcd/personal.pass
```

### `secret-service`

`kpxcd` connects to an existing Secret Service provider (gnome-keyring, kwallet) and looks up the database password by label and attributes. This is circular — `kpxcd` itself provides Secret Service — so this source is only useful for auto-unlock before `kpxcd` registers its own service.

Lookup attributes:

| Attribute | Value |
|-----------|-------|
| `application` | `kpxcd` |
| `dbname` | database `name` from config |

### `keyfile`

A keyfile is read from disk and used as a component of the composite key. Keyfiles can be:

- **XML keyfile v2** — KeePass format with `<Key><Data>` elements
- **XML keyfile v1** — Legacy format with base64 data
- **Raw binary** — Any file, SHA-256 hash is used as the key

### `prompt`

Do not attempt auto-unlock. The database remains locked until `kpxcctl unlock` is called.

### `none`

The database has no password. Use with caution — a `.kdbx` file with no password and no keyfile is trivially openable by anyone with read access to the file.