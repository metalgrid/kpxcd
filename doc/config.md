# kpxcd — Configuration Reference

`kpxcd` reads a single TOML configuration file at startup.

## File Location

| Precedence | Path |
|------------|------|
| Default | `~/.config/kpxcd/config.toml` |
| Override | `kpxcd --config <path>` |
| XDG | `$XDG_CONFIG_HOME/kpxcd/config.toml` (if `XDG_CONFIG_HOME` is set) |

If the default config file does not exist, `kpxcd` creates it from its embedded defaults with parent directory mode `0700` and file mode `0600`.

## Full Example

```toml
# config.toml — kpxcd configuration

[daemon]
# Lock all databases after this many seconds of inactivity (0 = disabled)
idle_timeout = 900

# Parsed but not wired yet: screen-lock auto-lock is not implemented.
lock_on_screenlock = false

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
path = "$XDG_DATA_HOME/kpxcd/default.kdbx"

# Display name (optional, defaults to filename)
name = "Default"

# Mark this database as the default Secret Service database.
default = true

# Auto-unlock this database when the daemon starts or when a PAM token appears.
auto_unlock = true

# Credential source for auto-unlock
# "pam"                — unwrap age-sealed credential using PAM login token
# "systemd-credential" — read from systemd LoadCredential
# "keyfile"            — read a keyfile from disk
# "prompt"             — do not auto-unlock; wait for kpxcctl unlock
# "none"               — database has no password (dangerous)
unlock_credential = "pam"

# Keyfile path (only used if unlock_credential = "keyfile")
keyfile = ""

# Reserved for YubiKey challenge-response plumbing; config validation does not enable it yet.
yubikey_slot = 0

# Which group to expose via Secret Service (empty = all groups)
secret_service_expose_group = ""

# Parsed but not enforced yet; SSH key auto-add is currently controlled globally.
ssh_auto_add = false

[secret_service]
# Whether to expose the Secret Service interface on D-Bus
enabled = true

# Show a desktop notification when a secret is retrieved
notify_on_access = true

# Require Polkit confirmation before returning a secret.
# When true, missing caller metadata or unavailable Polkit denies access.
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
# Reserved. Current D-Bus/CLI passkey methods return not implemented even if true.
enabled = false

# AAGUID to report in attestation objects
# (KeePassXC uses a fixed AAGUID for software authenticator)
aaguid = "f8a011f3-8c0a-4d15-8006-17111f9edc7d"

# Supported algorithms
# -7  = ES256 (ECDSA P-256 with SHA-256)
# -25 = ES256K (ECDSA secp256k1 with SHA-256)  
# -37 = PS256 (RSASSA-PSS with SHA-256)
# -8  = EdDSA (Ed25519)
algorithms = [-7, -8]

# Reserved user verification preference for future passkey operations.
user_verification = "preferred"  # "required" | "preferred" | "discouraged"
```

## Section Reference

### `[daemon]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `idle_timeout` | int | `0` | Seconds of inactivity before locking all databases. `0` disables. |
| `lock_on_screenlock` | bool | `false` | Parsed but not wired yet; screen-lock auto-lock is not implemented. |
| `log_level` | string | `"info"` | Minimum log severity. |
| `log_to_journald` | bool | `true` | Log to systemd journal instead of stderr. |
| `ssh_socket_path` | string | `"kpxcd/ssh.sock"` | Path relative to `$XDG_RUNTIME_DIR` for the SSH agent socket. |
| `ssh_mode` | string | `"agent"` | `"agent"` = act as SSH agent; `"proxy"`/`"client"` = push keys into existing `$SSH_AUTH_SOCK`. |

#### SSH_AUTH_SOCK setup

Run:

```bash
kpxcctl setup-ssh
```

The command inspects `ssh_mode` and writes the appropriate user-level systemd configuration:

- `ssh_mode = "agent"`: writes `~/.config/environment.d/kpxcd-ssh.conf` so future sessions export `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/kpxcd/ssh.sock`.
- `ssh_mode = "client"` or `"proxy"`: writes `~/.config/systemd/user/kpxcd.service.d/ssh-client.conf` with `PassEnvironment=SSH_AUTH_SOCK` so kpxcd can push keys into your existing agent.

### `[[database]]`

This is a TOML array of tables — repeat the `[[database]]` header for each database.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | *required* | Absolute path to the `.kdbx` file. |
| `name` | string | filename | Human-readable name for the database. |
| `default` | bool | `false` | Mark this as the default database. At most one database may be default. |
| `auto_unlock` | bool | `false` | Attempt to unlock this database when the daemon starts. |
| `unlock_credential` | string | `"prompt"` | How to obtain the password for auto-unlock. One of: `pam`, `systemd-credential`, `keyfile`, `prompt`, `none`. |
| `systemd_credential_name` | string | `""` | Name of the systemd credential holding the password. Only used when `unlock_credential = "systemd-credential"`. |
| `keyfile` | string | `""` | Path to a keyfile. Used when `unlock_credential = "keyfile"` or as a secondary factor. |
| `yubikey_slot` | int | `0` | Reserved for YubiKey challenge-response; current config validation does not enable `unlock_credential = "yubikey"`. |
| `secret_service_expose_group` | string | `""` | UUID or name of a group to restrict Secret Service exposure to. Empty = expose all. |
| `ssh_auto_add` | bool | `false` | Parsed but not enforced yet; SSH key auto-add currently ignores this per-database switch. |

### `[secret_service]`

Secret Service mode follows the GNOME Keyring/libsecret trust model: any same-user application in the unlocked login session can search exposed items and retrieve their secrets unless `require_confirmation = true`. Attributes are lookup metadata, not secret material; do not store secrets in fields you expect to expose as attributes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Expose `org.freedesktop.secrets` on the session bus. |
| `notify_on_access` | bool | `true` | Show a desktop notification when a secret is retrieved. |
| `require_confirmation` | bool | `false` | Require Polkit confirmation before returning any secret. If true, confirmation failures deny access. |
| `confirmation_timeout` | int | `30` | Seconds before confirmation dialog times out and is denied. `0` = no timeout. |

### `[ssh_agent]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Listen on the SSH agent socket. |
| `remove_on_lock` | bool | `true` | Remove identities from the agent when their database is locked. |
| `confirm_on_use` | bool | `false` | Parsed/stored but not enforced by kpxcd's built-in SSH agent yet. |
| `lifetime` | int | `0` | Parsed/stored but not enforced by kpxcd's built-in SSH agent yet. `0` = unlimited. |
| `security_key_provider` | string | `"internal"` | Security key provider for `sk-ssh-*` key types. `"internal"` = use built-in Go SSH implementation. |

### `[fido2]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Reserved; current D-Bus/CLI passkey methods return not implemented even if true. |
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
| `$XDG_DATA_HOME` | XDG data directory, fallback `~/.local/share` | `$XDG_DATA_HOME/kpxcd/default.kdbx` |
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

### `pam`

`pam` uses a Unix domain socket for secure PAM-to-daemon IPC. A small PAM module captures the login password during authentication, derives a kpxcd-specific token via HKDF-SHA256, and sends the derived token over a socket during session setup. The **raw password is never written to the filesystem.**

The PAM session hook must run **after `pam_systemd.so`**, because `pam_systemd` creates `$XDG_RUNTIME_DIR`.

kpxcd ships a systemd user socket unit (`kpxcd.socket`) that listens on:

```text
$XDG_RUNTIME_DIR/kpxcd/pam.sock
```

The `kpxcd.service` unit requires this socket. When the PAM module connects, kpxcd accepts the connection, reads the 32-byte derived token, and uses it to unwrap:

```text
$XDG_DATA_HOME/kpxcd/default.identity.age
```

which is an age X25519 identity encrypted with age passphrase mode. That identity decrypts:

```text
$XDG_DATA_HOME/kpxcd/default.cred.age
```

which contains the random password for the default KDBX database. The default database is:

```text
$XDG_DATA_HOME/kpxcd/default.kdbx
```

On first login, if the derived token is received and neither the default DB nor sealed credential exist, `kpxcd` creates all of them with private permissions. This preserves the convenient first-login bootstrap flow, but the first valid token received on the user-owned socket wins; avoid running untrusted same-UID processes before initial bootstrap. If the DB already exists but the sealed credential is missing, `kpxcd` refuses to modify it.

Enable the socket unit:

```bash
systemctl --user enable kpxcd.socket
```

Changing the Linux login password will require rewrapping the age identity; automatic password-change rewrap is future work.

### `systemd-credential`

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

### `keyfile`

A keyfile is read from disk and used as a component of the composite key. Keyfiles can be:

- **XML keyfile v2** — KeePass format with `<Key><Data>` elements
- **XML keyfile v1** — Legacy format with base64 data
- **Raw binary** — Any file, SHA-256 hash is used as the key

### `prompt`

Do not attempt auto-unlock. The database remains locked until `kpxcctl unlock` is called.

### `none`

The database has no password. Use with caution — a `.kdbx` file with no password and no keyfile is trivially openable by anyone with read access to the file.