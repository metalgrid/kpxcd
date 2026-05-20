# pam_kpxcd

Experimental PAM handoff module for kpxcd auto-unlock.

The module does **not** contact kpxcd. It captures the login token during PAM
authentication and writes it during session setup to:

```text
$XDG_RUNTIME_DIR/kpxcd/pam-token
```

kpxcd consumes and deletes this token, unwraps
`$XDG_DATA_HOME/kpxcd/default.identity.age`, decrypts
`$XDG_DATA_HOME/kpxcd/default.cred.age`, and unlocks or creates the default
`$XDG_DATA_HOME/kpxcd/default.kdbx` database.

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
`pam_systemd.so`, because `pam_systemd` creates `$XDG_RUNTIME_DIR`.

Example sketch only; adapt to your distro/display manager:

```pam
# auth phase: capture token
auth optional pam_kpxcd.so

# session phase: pam_systemd first, then write the token
session required pam_systemd.so
session optional pam_kpxcd.so
```

The module returns quickly and never blocks login on the daemon being available.

## Password changes

Changing the Linux login password will make the existing age-wrapped identity
undecryptable until kpxcd grows a `chauthtok`/rewrap flow.
