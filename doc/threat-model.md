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
| Decrypted database content | Process memory, protected by best-effort `mlockall` | **High** — all passwords, keys, notes |
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
- **Password retrieval via Secret Service**: Any process in the session can call `org.freedesktop.secrets` and retrieve exposed, unlocked passwords.
  - **Mitigation:** This intentionally matches GNOME Keyring/libsecret. If `require_confirmation = true`, Polkit `auth_self` is required for secret reads and failures deny access.
  - **Residual risk:** The default `require_confirmation = false` lets same-user session processes read exposed, unlocked secrets without confirmation.

- **PAM first-run bootstrap race**: Before the default database and sealed credential exist, the first valid-length token sent to the user-owned PAM socket can create the bootstrap state.
  - **Mitigation:** Socket lives under `$XDG_RUNTIME_DIR` with user-only permissions; this is a same-UID first-run race only.
  - **Residual risk:** Do initial bootstrap in a trusted login session before running untrusted same-user processes.

- **SSH key use**: Any process can request key listing and signing via the SSH agent socket.
  - **Mitigation:** Unix file permissions (`0600`) on the socket. Only the owning user can connect.
  - **Residual risk:** Any process running as the same user can connect. This is the same trust model as `ssh-agent`.

- **FIDO2 assertion**: Native UHID operations use an interactive polkit approval gate when UP or UV is requested. Silent CTAP probes request neither and do not prompt.
  - **Mitigation:** Denial, errors, timeout, cancellation and incomplete approval fail closed. See the fresh-authentication assumptions below.
  - **Residual risk:** A process reading an unlocked vault through other authorized interfaces can bypass the authenticator entirely. The separate local D-Bus/CLI API retains its own sender/polkit authorization; this native gate's cancellation/actual-verdict contract does not replace that API. Local API output is not proof of a native UHID ceremony.

- **Memory scanning**: A process with the same UID can read `/proc/$pid/mem`.
  - **Mitigation:** Linux `kernel.yama.ptrace_scope ≥ 1` (default on most distributions) prevents `ptrace` from non-child processes.
  - **Residual risk:** Child processes of `kpxcd` could still attach. `kpxcd` does not fork child processes.

### 2. Unprivileged Local Process (Different User)

**Capabilities:** None directly. Cannot connect to D-Bus or Unix sockets.

**Threats:**
- **Swap scanning**: If decrypted content is swapped to disk, another user with physical access could read it.
  - **Mitigation:** `kpxcd` calls `mlockall` at startup and uses `runtime/secret` scopes in sensitive paths.
  - **Residual risk:** If `mlock` fails (`RLIMIT_MEMLOCK` too low), `kpxcd` logs a warning but continues. The operator must ensure sufficient `memlock` limits.

- **File access**: If the `.kdbx` file or keyfile has overly permissive permissions.
  - **Mitigation:** New `kpxcd` state is created with private permissions.
  - **Residual risk:** Existing `.kdbx` files and keyfiles may still have permissive permissions; enforcing/warning on open is future hardening.

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
  - `$XDG_RUNTIME_DIR/kpxcd/pam.sock` (PAM token protocol, when enabled)

  Directly created SSH/PAM sockets are chmod'd `0600`; PAM socket activation
  relies on the systemd socket unit's permissions. The session bus is provided
  by the user's bus service, not created or chmod'd by kpxcd. There is no
  implemented `control.sock` JSON-RPC server.

### 6. Malicious D-Bus Client

**Capabilities:** Can call any method on `org.keepassxc.Daemon` or `org.freedesktop.secrets`.

**Threats:**
- **Bulk password extraction**: A malicious client calls `SearchEntries` then `GetEntry` for every result.
  - **Mitigation:** `GetEntry` does not return passwords. Secret Service reads can require Polkit when `require_confirmation = true`.
  - **Residual risk:** The default Secret Service mode follows GNOME Keyring: same-user apps can retrieve exposed, unlocked secrets.

- **SSH key abuse**: A malicious client connects to the SSH socket and signs arbitrary challenges.
  - **Mitigation:** File permissions on the socket.
  - **Residual risk:** `confirm_on_use` and `lifetime` are parsed/stored but not enforced by the built-in agent yet; same-user apps can request signatures while keys are loaded.

## Attack Surface Summary

| Interface | Protocol | Attack Surface |
|-----------|----------|---------------|
| D-Bus session bus | Binary D-Bus | Method calls, signal injection |
| `kpxcd/ssh.sock` | SSH agent protocol | Binary protocol parsing |
| `kpxcd/pam.sock` (when enabled) | PAM token protocol | Token parsing, unlock/bootstrap |
| Linux UHID (when enabled) | CTAPHID/CTAP2 | Report reassembly, CBOR parsing, approval |
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
| Explicit private directory/file modes | Private newly created daemon state | Accidental exposure of new state |

### Filesystem

| Mitigation | Mechanism | Protects Against |
|------------|-----------|------------------|
| Existing vault/keyfile permission checks (future hardening, not implemented) | Operator must verify permissions; no startup warning is provided | No current enforcement |
| Encrypted home directory (recommended) | LUKS / ecryptfs | Offline disk access |

## Native FIDO2 approval assumptions

The shipped `org.keepassxc.daemon.passkey.create` and `.assert` actions use
`auth_self`, not `auth_self_keep`, in all three session states. A successful
interactive check is interpreted as actual UP **and** UV under the assumption
that the configured generic polkit agent freshly authenticates the daemon's
own user for this request. There is no dependency on a specific PAM method,
biometric system or agent. This is a deployment-policy assumption, **not a live
security verification**. A local `yes` override, `auth_self_keep`, retained/cached
authorization or an agent that approves without fresh authentication invalidates
the claim. The D-Bus `is_authorized` bit does not itself prove freshness or the
method used. Operators must keep those policies aligned; this change neither
inspects nor changes installed policy.

Each pending check has a distinct cancellation ID on a private system-bus
connection. Cancellation, deadline, HID resynchronization and close propagate
through the existing operation context. The gate sends `CancelCheckAuthorization`
with that ID **on the same connection after CheckAuthorization dispatch**, waits
at most two seconds for acknowledgment, then closes the connection. Gate shutdown closes admission, cancels all pending
checks and waits for bounded cleanup before the daemon exits. Connection
setup and each socket write are also bounded to two seconds; a stalled dispatch
can therefore add up to two seconds before cancellation cleanup begins. Local
cancellation of a godbus call alone does not dismiss a server-side prompt.
Late success is refused; operation-generation checks additionally suppress stale
HID output and continuation state. Cancellation can race an already completed
check (polkit may return “no such cancellation ID”). A server/agent failure can
prevent prompt dismissal; it never grants approval. No cancellation mechanism
rolls back a storage mutation that has already completed.

Only Linux Unix system-bus addresses (`unix:path=...` or `unix:abstract=...`,
optionally with `guid`) are supported by this bounded authorization connection.
Unsupported, ambiguous or multi-address `DBUS_SYSTEM_BUS_ADDRESS` settings fail
closed, without selecting another bus. godbus still performs the D-Bus handshake,
encoding and reply handling; no file descriptor passing is needed for these calls.

Prompt attribution uses the shipped fixed create/assert action messages. The
primary polkit API warns that nonempty CheckAuthorization details, including
`polkit.message`, require a sufficiently authorized caller (for example root).
An unprivileged user daemon therefore sends empty details rather than relying on
a privileged message override. No RP, account name, untrusted markup or command
is interpolated. This avoids spoofable or sensitive prompt text but does not
provide verified browser-origin attribution. Production FIDO request paths log
fixed status/error messages, not full CBOR/request bodies, RP/account names,
credential IDs, handles or private storage-error text. Tests use isolated fakes;
no live prompt, kernel device or browser compatibility is established here.

## Out of Scope

- **Side-channel attacks** (timing, power, cache): Not defended against beyond what Go's runtime provides.
- **Kernel exploitation**: If the kernel is compromised, all user-space defenses are void.
- **Supply chain attacks**: `kpxcd` depends on Go standard library and vetted third-party modules. Dependency pinning and reproducible builds mitigate this in the build process, not at runtime.
- **Phishing / social engineering**: `kpxcd` cannot prevent the user from entering their password into a malicious UI.
- **Compromised Polkit agent**: If the Polkit authentication agent is malicious, it can approve any request. This is a system-level concern, not specific to `kpxcd`.
