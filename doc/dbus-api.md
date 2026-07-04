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
| `credential_type` | `s` | Currently implemented: `"password"`, `"keyfile"`, `"none"`; config auto-unlock also supports `"systemd-credential"` and `"pam"` paths. |
| `credential` | `v` | Varies by implemented type: password → `s`, keyfile → `s` (path), none → ignored |

Returns `true` on success. Raises `org.keepassxc.Daemon.Error.Locked` if already unlocked, `org.keepassxc.Daemon.Error.InvalidKey` if the credential is wrong.

**Authorization:** same-UID D-Bus caller check.

#### `LockDatabase(uuid: s) → b`

Lock a database by UUID. Clears decrypted data from memory (inside `runtime/secret.Do`).

Returns `true` on success. Raises `org.keepassxc.Daemon.Error.NotFound` if the UUID is unknown.

**Authorization:** same-UID D-Bus caller check.

#### `LockAll() → b`

Lock all unlocked databases. Called by user request or idle timeout; screen-lock integration is not wired yet.

Returns `true` on success.

**Authorization:** same-UID D-Bus caller check.

#### `GetEntry(uuid: s, entry_path: s) → a{sv}`

Retrieve entry fields by database UUID and entry path (slash-separated group path, e.g., `/General/example.com`).

```json
{
  "title": "s",
  "username": "s",
  "url": "s",
  "uuid": "s"
}
```

**Authorization:** same-UID D-Bus caller check. No password or notes are returned.

#### `SearchEntries(uuid: s, query: s) → aa{sv}`

Search entries in a database by title, URL, or username. Returns a list of partial entry dictionaries with no secret fields.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID, or `""` to search all databases |
| `query` | `s` | Search term (matched against title, URL, username) |

Returns entries without secret fields. Empty queries are rejected to avoid accidental full-vault enumeration.

#### `GetTotp(uuid: s, entry_path: s) → s`

Reserved for retrieving a TOTP code. The current daemon returns a D-Bus failure.

Reserved future return shape: `"123456:28"` (code `:` seconds remaining).

**Authorization:** same-UID D-Bus caller check.

#### `GeneratePassword(length: i, charset: s) → s`

Generate a random password.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

| Parameter | Type | Description |
|-----------|------|-------------|
| `length` | `i` | Password length (8-128) |
| `charset` | `s` | Character set: `"ascii"`, `"alphanumeric"`, `"digits"`, `"hex"`, or custom characters |

**Authorization:** same-UID D-Bus caller check.

#### `GeneratePassphrase(word_count: i, separator: s) → s`

Generate a diceware passphrase.

> Implementation status: not yet implemented; current daemon returns a D-Bus failure.

| Parameter | Type | Description |
|-----------|------|-------------|
| `word_count` | `i` | Number of words (4-20) |
| `separator` | `s` | Word separator (default: `"-"`) |

**Authorization:** same-UID D-Bus caller check.

### SSH Agent Methods

#### `SshListKeys(uuid: s) → aa{sv}`

List SSH keys loaded in the built-in agent. If `uuid` is non-empty, only loaded keys from that database are returned.

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

Add an SSH key from an entry to the agent. `lifetime` and `confirm` are accepted for OpenSSH-agent compatibility, but the built-in agent does not enforce them yet.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID |
| `entry_path` | `s` | Entry path |
| `lifetime` | `i` | Key lifetime in seconds (0 = unlimited) |
| `confirm` | `b` | Require confirmation before each use |

**Authorization:** same-UID D-Bus caller check.

#### `SshRemoveKey(fingerprint: s) → b`

Remove an SSH key from the agent by its fingerprint.

**Authorization:** same-UID D-Bus caller check.

#### `SshExportKey(fingerprint: s) → ay`

Disabled. The daemon returns a failure; kpxcd exposes loaded SSH keys for signing, not private-key extraction.

**Authorization:** same-UID D-Bus caller check.

### FIDO2 / Passkey Methods

#### `CreatePasskey(uuid: s, rp_id: s, rp_name: s, user_name: s, user_display_name: s, algorithms: ai) → a{sv}`

Not implemented. The D-Bus method currently returns a failure.

> Implementation status: experimental; credential material can be created, but database storage is not complete.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | `s` | Database UUID |
| `rp_id` | `s` | Relying party identifier (e.g., `"github.com"`) |
| `rp_name` | `s` | Relying party display name |
| `user_name` | `s` | User name |
| `user_display_name` | `s` | User display name |
| `algorithms` | `ai` | Preferred COSE algorithm IDs (e.g., `[-7, -8]`) |

Reserved future response shape:

```json
{
  "credential_id": "s",    // Base64url-encoded
  "public_key": "s",        // Base64url-encoded COSE key
  "entry_path": "s"         // Path of the new entry
}
```

**Authorization:** same-UID D-Bus caller check.

#### `AssertPasskey(rp_id: s, credential_id: s, challenge: s, origin: s) → a{sv}`

Not implemented. The D-Bus method currently returns a failure.

> Implementation status: not yet fully implemented; storage/extraction and signing are incomplete.

| Parameter | Type | Description |
|-----------|------|-------------|
| `rp_id` | `s` | Relying party identifier |
| `credential_id` | `s` | Base64url-encoded credential ID |
| `challenge` | `s` | Base64url-encoded challenge from the relying party |
| `origin` | `s` | Origin URL |

Reserved future response shape:

```json
{
  "authenticator_data": "s",  // Base64url-encoded
  "signature": "s",           // Base64url-encoded
  "user_handle": "s"          // Base64url-encoded
}
```

**Authorization:** same-UID D-Bus caller check.

### Signals

#### `DatabaseUnlocked(uuid: s)`

Emitted when a database is successfully unlocked.

#### `DatabaseLocked(uuid: s)`

Emitted when a database is locked manually or by idle timeout. Screen-lock integration is not wired yet.

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
| `org.keepassxc.Daemon.Error.PermissionDenied` | Authorization failed |

## Polkit Actions

`kpxcd` installs a Polkit policy file at `/usr/share/polkit-1/actions/org.keepassxc.daemon.policy`. The custom `org.keepassxc.Daemon` methods currently use a same-UID D-Bus caller check; the Secret Service `require_confirmation=true` path uses `org.keepassxc.daemon.get-entry.secret`. Other actions are reserved for future custom-D-Bus confirmation.

| Action ID | Default | Description |
|-----------|---------|-------------|
| `org.keepassxc.daemon.unlock` | `auth_self` | Unlock a database |
| `org.keepassxc.daemon.lock` | `yes` | Lock a database |
| `org.keepassxc.daemon.get-entry.secret` | `auth_self` | Secret Service read confirmation when `require_confirmation = true` |
| `org.keepassxc.daemon.get-totp` | `auth_self` | Reserved for future TOTP retrieval |
| `org.keepassxc.daemon.ssh.add` | `yes` | Add an SSH key |
| `org.keepassxc.daemon.ssh.remove` | `auth_self` | Remove an SSH key |
| `org.keepassxc.daemon.passkey.create` | `auth_self` | Reserved; D-Bus method currently returns not implemented |
| `org.keepassxc.daemon.passkey.assert` | `yes` | Reserved; D-Bus method currently returns not implemented |

`yes` = allowed by default. `auth_self` = requires the user to authenticate with their own password.