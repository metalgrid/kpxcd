# FIDO2 Passkeys

kpxcd serves FIDO2 passkeys to browsers as a virtual CTAP2 security
key. The credentials live in the KeePass database, the signing happens
locally, and nothing ever leaves the machine.

To our knowledge, kpxcd is the only free and open-source way to get
fully offline, extensionless passkeys on Linux that every major browser
uses as a plain hardware security key. Browser passkey features elsewhere
are bound to a vendor cloud (Chrome/Google Password Manager, iCloud
Keychain) or require a proprietary app plus a browser extension
(1Password, Bitwarden). KeePassXC supports passkeys but needs its GUI
running and the KeePassXC-Browser extension. kpxcd needs neither: the
browser discovers a standard CTAP2 HID device, the same way a YubiKey
appears.

## How It Works

1. The daemon opens `/dev/uhid` and registers a virtual HID device
   with the FIDO Alliance usage page. Browsers enumerate it through
   the kernel's normal CTAP2 HID transport — no extension, no
   configuration in the browser.
2. Register (MakeCredential) and sign-in (GetAssertion) run as
   standard CTAP2 commands against credentials stored as KeePass
   entries: private key PKCS#8, credential ID, user handle, sign
   counter.
3. Every credential operation is gated by polkit. The polkit agent in
   your session decides what "touch your key" means: a zdr face scan,
   a password prompt, whatever your desktop provides. The gate
   performs user presence for every ceremony and user verification
   whenever the site requires it.
4. Assertions are signed locally with ES256 and returned over the
   same transport. The challenge, origin binding and RP hash are
   handled per the CTAP 2.0 specification; no network access happens
   at any point.

Both Chrome and Firefox have been verified against webauthn.io and
GitHub: registration, username-less sign-in, sign-in with
`allowCredentials`, and user verification.

## Requirements

- Linux with `/dev/uhid` (kernel module `uhid`; the package loads it
  via `modules-load.d`)
- The packaged udev rule grants the seated user access to `/dev/uhid`
- A polkit authentication agent running in your session (GNOME and
  KDE provide one; on bare window managers start any agent, for
  example `polkit-kde-authentication-agent-1`)
- `fido2.enabled = true` in the configuration (off by default)

## Enabling Passkeys

```toml
[fido2]
enabled = true
```

Then restart the daemon:

```sh
systemctl --user restart kpxcd
```

The journal confirms the device came up:

```
hid: virtual FIDO device created
```

## Credential Model

| Property | Behavior |
|---|---|
| Storage | KeePass entry in the default database, Passkeys group |
| Keys | ECDSA P-256 (ES256), PKCS#8 inside the entry |
| Discoverability | Resident-style: the credential is looked up by RP ID, username-less sign-in works |
| User presence | Gate approval per ceremony |
| User verification | Gate approval per ceremony when the site requires UV (`uv` advertised) |
| Sign counter | Persisted and monotonically increasing |
| AAGUID | KeePassXC's AAGUID by default, configurable |

Because credentials are ordinary KeePass entries, they inherit vault
semantics: locking the database locks the passkeys, backups back up
the passkeys, and the Bitwarden import writes regular entries.

## Bitwarden Import

Passkeys created in Bitwarden can be moved to kpxcd:

```sh
kpxcctl passkey import <db-uuid> bitwarden-export.json --dry-run
kpxcctl passkey import <db-uuid> bitwarden-export.json
```

The importer reads the decrypted Bitwarden JSON export
(`login.fido2Credentials`), carries over credential ID, user handle,
RP ID and sign counter, and converts the ES256 private key. Notes:

- UUID-shaped credential IDs (GitHub, Amazon) are stored as their
  16 wire bytes.
- Only ECDSA P-256 keys can be imported.
- The credential replaces Bitwarden as the signer: both apps track
  independent sign counters, so retire the Bitwarden copy after
  importing or sites that enforce monotonic counters will reject the
  stale one.
- The export file contains live private keys. Delete it after
  importing.

## Limitations

- Linux only.
- One assertion per ceremony: every sign-in asks for one approval.
  This is required by WebAuthn and is not negotiable.
- No clientPin (user verification is the gate instead), no
  credProtect, no largeBlob, no caBLE, no hmac-secret/prf.
- A polkit agent must be running in the session, or ceremonies time
  out without a prompt.
- Passkeys are only as available as the vault: locking the database
  locks the passkeys, and an offline vault is an offline
  authenticator.
