# kpxcd — D-Bus API Specification

`kpxcd` exposes two D-Bus interfaces on the session bus:

1. **`org.keepassxc.Daemon`** — kpxcd-specific management and query API
2. **`org.freedesktop.secrets`** — standard Secret Service specification v0.2

This document covers only `org.keepassxc.Daemon`. The Secret Service implementation follows the [freedesktop.org specification](https://specifications.freedesktop.org/secret-service-spec/0.2/) and is documented separately in its conformance notes.

## Bus and Path

| Property | Value |
|----------|-------|
| Bus | Session |
| Service name | `org.keepassxc.Daemon` |
| Object path | `/org/keepassxc/Daemon` |

## Interface: `org.keepassxc.Daemon`

### Methods

#### `Ping() → s`

Returns `"pong"`. Used to verify the daemon is alive.

#### `ListDatabases() → aa{sv}`

Returns an array of dictionaries describing known databases:

```json
[
  {
    "uuid": "s",       // Database UUID (string form)
    "name": "s",       // Display name
    "path": "s",       // File path on disk
    "locked": "b",     // Whether the database is currently locked
    "auto_unlock": "b" // Whether auto-unlock is configured
  }
]
```

#### `UnlockDatabase(path: s, credential_type: s, credential: v) → b`

Unlock a database by path.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `s` | Absolute path to the `.kdbx` file |
| `credential_type` | `s` | One of: `"password"`, `"keyfile"`, `"password+keyfile"`, `"yubikey"`, `"systemd-credential"`, `"none"` |
| `credential` | `v` | Varies by type: password → `s`, keyfile → `s` (path), password+keyfile → `(ss)`, yubikey → `i` (slot), systemd-credential → `s` (name) |

Returns `true` on success. Raises `org.keepassxc.Daemon.Error.Locked` if already unlocked, `org.keepassxc.Daemon.Error.InvalidKey` if the credential is wrong.

**Polkit action:** `org.keepassxc.daemon.unlock`

#### `LockDatabase(uuid: s) → b`

Lock a database by UUID. Clears decrypted data from memory (inside `runtime/secret.Do`).

Returns `true` on success. Raises `org.keepassxc.Daemon.Error.NotFound` if the UUID is unknown.

**Polkit action:** `org.keepassxc.daemon.lock`

#### `LockAll() → b`

Lock all unlocked databases. Called on screen lock, session end, or user request.

Returns `true` on success.

**Polkit action:** `org.keepassxc.daemon.lock`

#### `GetEntry(uuid: s, entry_path: s) → a{sv}`

Retrieve entry fields by database UUID and entry path (slash-separated group path, e.g., `/General/example.com`).

```json
{
  "title": "s",
  "username": "s",
  "password": "s",     // Requires Polkit authorization
  "url": "s",
  "notes": "s",
  "totp": "s",          // Current TOTP code, if configured
  "attributes": "a{ss}", // Custom attributes
  "tags": "as",
  "uuid": "s",
  "icon": "i"
}
```

**Polkit action:** `org.keepassxc.daemon.get-entry.secret` (for the `password` field)

#### `SearchEntries(uuid: s, query: s) → aa{sv}`

Search entries in a database by title, URL, or username. Returns a list of partial entry dictionaries (no secret fields unless authorized).

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID, or `""` to search all databases |
| `query` | `s` | Search term (matched against title, URL, username) |

Returns entries without the `password` field. Use `GetEntry` to retrieve secrets.

#### `GetTotp(uuid: s, entry_path: s) → s`

Get the current TOTP code for an entry. Returns the 6-8 digit code and remaining seconds validity.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

Returns `"123456:28"` (code `:` seconds remaining).

**Polkit action:** `org.keepassxc.daemon.get-totp`

#### `GeneratePassword(length: i, charset: s) → s`

Generate a random password.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

| Parameter | Type | Description |
|-----------|------|-------------|
| `length` | `i` | Password length (8-128) |
| `charset` | `s` | Character set: `"ascii"`, `"alphanumeric"`, `"digits"`, `"hex"`, or custom characters |

**Polkit action:** None (no secret access)

#### `GeneratePassphrase(word_count: i, separator: s) → s`

Generate a diceware passphrase.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

| Parameter | Type | Description |
|-----------|------|-------------|
| `word_count` | `i` | Number of words (4-20) |
| `separator` | `s` | Word separator (default: `"-"`) |

**Polkit action:** None

### SSH Agent Methods

#### `SshListKeys(uuid: s) → aa{sv}`

List SSH key entries in a database.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

```json
[
  {
    "fingerprint": "s",      // SHA256 fingerprint
    "comment": "s",          // Key comment
    "type": "s",              // Key type (e.g., "ssh-ed25519")
    "entry_path": "s",       // Entry path in the database
    "loaded": "b"             // Whether the key is currently loaded in the agent
  }
]
```

#### `SshAddKey(uuid: s, entry_path: s, lifetime: i, confirm: b) → b`

Add an SSH key from an entry to the agent.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID |
| `entry_path` | `s` | Entry path |
| `lifetime` | `i` | Key lifetime in seconds (0 = unlimited) |
| `confirm` | `b` | Require confirmation before each use |

**Polkit action:** `org.keepassxc.daemon.ssh.add`

#### `SshRemoveKey(fingerprint: s) → b`

Remove an SSH key from the agent by its fingerprint.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

**Polkit action:** `org.keepassxc.daemon.ssh.remove`

### FIDO2 / Passkey Methods

#### `CreatePasskey(uuid: s, rp_id: s, rp_name: s, user_name: s, user_display_name: s, algorithms: ai) → a{sv}`

Create a new FIDO2 credential (passkey).

> Implementation status: experimental; credential material can be created, but database storage is not complete.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID |
| `rp_id` | `s` | Relying party identifier (e.g., `"github.com"`) |
| `rp_name` | `s` | Relying party display name |
| `user_name` | `s` | User name |
| `user_display_name` | `s` | User display name |
| `algorithms` | `ai` | Preferred COSE algorithm IDs (e.g., `[-7, -8]`) |

Returns:

```json
{
  "credential_id": "s",    // Base64url-encoded
  "public_key": "s",        // Base64url-encoded COSE key
  "entry_path": "s"         // Path of the new entry
}
```

**Polkit action:** `org.keepassxc.daemon.passkey.create`

#### `AssertPasskey(rp_id: s, credential_id: s, challenge: s, origin: s) → a{sv}`

Assert (authenticate with) a FIDO2 credential.

> Implementation status: not yet fully implemented; storage/extraction and signing are incomplete.

| Parameter | Type | Description |
|-----------|------|-------------|
| `rp_id` | `s` | Relying party identifier |
| `credential_id` | `s` | Base64url-encoded credential ID |
| `challenge` | `s` | Base64url-encoded challenge from the relying party |
| `origin` | `s` | Origin URL |

Returns:

```json
{
  "authenticator_data": "s",  // Base64url-encoded
  "signature": "s",           // Base64url-encoded
  "user_handle": "s"          // Base64url-encoded
}
```

**Polkit action:** `org.keepassxc.daemon.passkey.assert`

### Signals

#### `DatabaseUnlocked(uuid: s)`

Emitted when a database is successfully unlocked.

#### `DatabaseLocked(uuid: s)`

Emitted when a database is locked (manually, by timeout, or by screen lock).

#### `DaemonReady()`

Emitted when the daemon has finished initialization and is ready to serve requests.

#### `DaemonStopping()`

Emitted when the daemon is shutting down.

### Error Names

| D-Bus Error Name | Description |
|-------------------|-------------|
| `org.keepassxc.Daemon.Error.NotFound` | Database or entry not found |
| `org.keepassxc.Daemon.Error.Locked` | Database is locked |
| `org.keepassxc.Daemon.Error.InvalidKey` | Wrong password or keyfile |
| `org.keepassxc.Daemon.Error.AlreadyUnlocked` | Database is already unlocked |
| `org.keepassxc.Daemon.Error.IO` | File I/O error |
| `org.keepassxc.Daemon.Error.Corrupt` | Database file is corrupt |
| `org.keepassxc.Daemon.Error.PermissionDenied` | Polkit authorization failed |

## Polkit Actions

`kpxcd` installs a Polkit policy file at `/usr/share/polkit-1/actions/org.keepassxc.daemon.policy`.

| Action ID | Default | Description |
|-----------|---------|-------------|
| `org.keepassxc.daemon.unlock` | `auth_self` | Unlock a database |
| `org.keepassxc.daemon.lock` | `yes` | Lock a database |
| `org.keepassxc.daemon.get-entry.secret` | `auth_self` | Retrieve a password |
| `org.keepassxc.daemon.get-totp` | `auth_self` | Retrieve a TOTP code |
| `org.keepassxc.daemon.ssh.add` | `yes` | Add an SSH key |
| `org.keepassxc.daemon.ssh.remove` | `auth_self` | Remove an SSH key |
| `org.keepassxc.daemon.passkey.create` | `auth_self` | Create a passkey |
| `org.keepassxc.daemon.passkey.assert` | `yes` | Authenticate with a passkey |

`yes` = allowed by default. `auth_self` = requires the user to authenticate with their own password.