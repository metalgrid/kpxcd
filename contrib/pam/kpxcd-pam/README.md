# pam_kpxcd

PAM handoff module for kpxcd auto-unlock.

The module does **not** write any credentials to disk. It captures the login
password during PAM authentication, derives a kpxcd-specific token via
HKDF-SHA256, and sends that derived token to the kpxcd daemon over a Unix
domain socket during session setup.

## Protocol

1. During `auth`, the module captures `pam_authtok` and derives a 32-byte
   token via `HKDF-SHA256(password, salt="kpxcd-pam-v1", info="")`.
2. During `open_session`, the module connects to
   `$XDG_RUNTIME_DIR/kpxcd/pam.sock` and sends the 32-byte derived token.
3. The connection is closed immediately after sending.
4. kpxcd uses the derived token as the passphrase to unwrap an age X25519
   identity, which decrypts the database credential.

The raw password is never written to the filesystem. The derived token is
kpxcd-specific: leaking it does not reveal the user's Unix login password.

## Build

```bash
cargo build --release
```

The resulting module is usually installed as something like:

```text
/lib/security/pam_kpxcd.so
```

(the exact PAM module directory is distribution-specific).

## PAM ordering

Use both auth and session hooks. The session hook must run **after**
`pam_systemd.so`, because `pam_systemd` creates `$XDG_RUNTIME_DIR` and the
kpxcd daemon (started by systemd) needs it to create the PAM socket.

Example sketch only; adapt to your distro/display manager:

```pam
# auth phase: capture and derive token
auth optional pam_kpxcd.so

# session phase: pam_systemd first, then send token to daemon
session required pam_systemd.so
session optional pam_kpxcd.so
```

The module returns quickly and never blocks login on the daemon being available.
If the socket does not exist or the connection fails, the module returns
`PAM_SUCCESS` silently.

## systemd socket unit

kpxcd ships a systemd user socket unit `kpxcd.socket` that listens on
`$XDG_RUNTIME_DIR/kpxcd/pam.sock` with mode 0600. The service unit
`kpxcd.service` requires this socket. If the daemon has not started when the
PAM module connects, the kernel queues the connection until kpxcd accepts it.

Enable the socket:

```bash
systemctl --user enable kpxcd.socket
```

## Password changes

Changing the Linux login password will make the existing age-wrapped identity
undecryptable until kpxcd grows a `chauthtok`/rewrap flow.
