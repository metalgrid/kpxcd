# kpxcd — Threat Model

## System Overview

`kpxcd` is a long-running user-space daemon on a Linux system. It holds decrypted KeePass databases in memory and serves their contents over D-Bus (Secret Service and a custom API) and a Unix domain socket (SSH agent protocol).

The threat model assumes:
- The system is a single-user Linux workstation.
- The user has an unprivileged account.
- Other users on the system are not trusted.
- The root account is not compromised.
- The D-Bus session bus is trusted (it is per-user by default on modern systems).
- The filesystem permissions are correctly set.

## Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Master password | Process memory, `runtime/secret` scope | **Critical** — decrypts everything |
| Derived composite key | Process memory, `runtime/secret` scope | **Critical** — equivalent to the master password |
| Decrypted database content | Process memory, `mlock`'d | **High** — all passwords, keys, notes |
| SSH private keys | Process memory, `runtime/secret` scope | **High** — can authenticate as the user |
| Passkey private keys | Process memory, `runtime/secret` scope | **High** — can authenticate to web services |
| TOTP seeds | Process memory, `mlock`'d | **Medium** — time-limited but reusable |
| Configuration file | `~/.config/kpxcd/config.toml` | **Low** — paths and settings, no secrets |
| Database files on disk | `~/Passwords.kdbx` etc. | **Low** — encrypted at rest |
| Keyfile on disk | Configured path | **Medium** — component of the composite key |

## Threat Actors

### 1. Unprivileged Local Process (Same User)

**Capabilities:** Can connect to D-Bus session bus, can connect to `kpxcd/ssh.sock`.

**Threats:**
- **Password retrieval via Secret Service**: Any process in the session can call `org.freedesktop.secrets` and retrieve passwords.
  - **Mitigation:** Polkit `auth_self` for `org.keepassxc.daemon.get-entry.secret`. The user must confirm via an authentication dialog.
  - **Residual risk:** If `require_confirmation = false` in config, any process in the session can retrieve passwords without confirmation.

- **SSH key use**: Any process can request key listing and signing via the SSH agent socket.
  - **Mitigation:** Unix file permissions (`0600`) on the socket. Only the owning user can connect.
  - **Residual risk:** Any process running as the same user can connect. This is the same trust model as `ssh-agent`.

- **FIDO2 assertion**: Any process can call `AssertPasskey` via D-Bus.
  - **Mitigation:** Polkit `yes` by default (passkeys are meant for authentication; requiring confirmation every time defeats the purpose).

- **Memory scanning**: A process with the same UID can read `/proc/$pid/mem`.
  - **Mitigation:** Linux `kernel.yama.ptrace_scope ≥ 1` (default on most distributions) prevents `ptrace` from non-child processes.
  - **Residual risk:** Child processes of `kpxcd` could still attach. `kpxcd` does not fork child processes.

### 2. Unprivileged Local Process (Different User)

**Capabilities:** None directly. Cannot connect to D-Bus or Unix sockets.

**Threats:**
- **Swap scanning**: If decrypted content is swapped to disk, another user with physical access could read it.
  - **Mitigation:** `mlock` on all pages containing decrypted data. `runtime/secret` scopes ensure registers and stack are scrubbed.
  - **Residual risk:** If `mlock` fails (`RLIMIT_MEMLOCK` too low), `kpxcd` logs a warning but continues. The operator must ensure sufficient `memlock` limits.

- **File access**: If the `.kdbx` file or keyfile has overly permissive permissions.
  - **Mitigation:** `kpxcd` checks that database files and keyfiles are not world-readable at startup and warns if they are.
  - **Residual risk:** The operator may ignore the warning.

### 3. Root Compromise

**Capabilities:** Full system access.

**Threats:**
- Full memory access, key extraction, arbitrary code injection.
- **Mitigation:** None. If root is compromised, the system is fully owned.
- **Design choice:** `kpxcd` does not attempt to defend against root. This is consistent with the Linux security model: root is outside the threat boundary.

### 4. Physical Access (Cold Boot)

**Capabilities:** Extract DRAM contents after power-off.

**Threats:**
- Decrypted content persists in DRAM for seconds to minutes after power-off.
  - **Mitigation:** `mlock` prevents swap-out but does not prevent DRAM retention. Hibernation should encrypt the suspend image (LUKS).
  - **Residual risk:** Suspend-to-RAM leaves content in DRAM. Suspend-to-disk with LUKS encryption mitigates this.

### 5. Network Attacker

**Capabilities:** None directly. `kpxcd` does not listen on any network interface.

**Threats:**
- None. `kpxcd` binds to:
  - D-Bus session bus (Unix socket, per-user)
  - `$XDG_RUNTIME_DIR/kpxcd/ssh.sock` (Unix socket, per-user)
  - `$XDG_RUNTIME_DIR/kpxcd/control.sock` (Unix socket, per-user)

  All are `0600` and bound to the user's runtime directory.

### 6. Malicious D-Bus Client

**Capabilities:** Can call any method on `org.keepassxc.Daemon` or `org.freedesktop.secrets`.

**Threats:**
- **Bulk password extraction**: A malicious client calls `SearchEntries` then `GetEntry` for every result.
  - **Mitigation:** Each `GetEntry` with `password` field requires Polkit `auth_self`. The user will see repeated authentication dialogs.
  - **Residual risk:** If the user dismisses the dialog without reading it, or if `require_confirmation = false`, extraction is possible.

- **SSH key abuse**: A malicious client connects to the SSH socket and signs arbitrary challenges.
  - **Mitigation:** File permissions on the socket. If `confirm_on_use = true`, `ssh-add -c` style confirmation is required for each sign operation.
  - **Residual risk:** Default is `confirm_on_use = false`, same trust model as `ssh-agent`.

## Attack Surface Summary

| Interface | Protocol | Attack Surface |
|-----------|----------|---------------|
| D-Bus session bus | Binary D-Bus | Method calls, signal injection |
| `kpxcd/ssh.sock` | SSH agent protocol | Binary protocol parsing |
| `kpxcd/control.sock` | JSON-RPC | JSON parsing, command dispatch |
| `$PATH/*.kdbx` | KDBX binary format | File parsing, crypto |
| `config.toml` | TOML | Config parsing |
| `org.freedesktop.PolicyKit1` | D-Bus | Polkit result spoofing (requires separate vuln) |

## Mitigations by Layer

### Memory

| Mitigation | Mechanism | Protects Against |
|------------|-----------|------------------|
| `runtime/secret.Do()` | Registers, stack, heap zeroing | Memory inspection after return |
| `unix.Mlock()` | Prevent swap-out | Swap scanning, cold boot (partially) |
| `security.Wipe()` | Explicit `memset(0)` + `Munlock()` | Use-after-free, stale pointer dereference |
| `kernel.yama.ptrace_scope ≥ 1` | Kernel enforcement | Cross-process memory reading |

### D-Bus

| Mitigation | Mechanism | Protects Against |
|------------|-----------|------------------|
| Polkit `auth_self` | Authentication dialog for sensitive calls | Unauthorized secret retrieval |
| Polkit `yes` | Allow without auth for non-secret operations | — (by design) |
| Bus name ownership | `org.keepassxc.Daemon` claimed at startup | Name spoofing |

### Unix Sockets

| Mitigation | Mechanism | Protects Against |
|------------|-----------|------------------|
| `0600` permissions | Only owner can connect | Cross-user socket access |
| `$XDG_RUNTIME_DIR` | Per-user, per-session directory | Path traversal, symlink attacks |
| `umask 0077` at daemon start | Ensures created files are owner-only | Accidental world-readable files |

### Filesystem

| Mitigation | Mechanism | Protects Against |
|------------|-----------|------------------|
| Permission check at startup | Warn if `.kdbx` or keyfile is world-readable | Accidental exposure |
| Encrypted home directory (recommended) | LUKS / ecryptfs | Offline disk access |

## Out of Scope

- **Side-channel attacks** (timing, power, cache): Not defended against beyond what Go's runtime provides.
- **Kernel exploitation**: If the kernel is compromised, all user-space defenses are void.
- **Supply chain attacks**: `kpxcd` depends on Go standard library and vetted third-party modules. Dependency pinning and reproducible builds mitigate this in the build process, not at runtime.
- **Phishing / social engineering**: `kpxcd` cannot prevent the user from entering their password into a malicious UI.
- **Compromised Polkit agent**: If the Polkit authentication agent is malicious, it can approve any request. This is a system-level concern, not specific to `kpxcd`.