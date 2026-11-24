# Native FIDO2 passkeys

kpxcd implements a Linux UHID CTAP2 authenticator backed by KeePass entries.
Browsers discover the FIDO HID usage page through the kernel, without an extension
or KeePassXC GUI. Private keys stay local; browsers receive public keys and signed
assertions and communicate with the relying party over their own network connection.
The browser validates origins and constructs clientDataHash; kpxcd binds credentials
and authenticator data to the supplied RP ID. This is not origin verification by
the daemon or a claim of universal site compatibility.

## Status and deployment prerequisites

The current candidate has offline regression evidence, not completed live browser
verification. Earlier reports of Chrome/Firefox working on webauthn.io and GitHub
predate these repairs and are not validation of this candidate. See the explicit
[verification matrix](fido2-conformance.md#browser-verification-matrix-awaiting-approval).
Amazon's server rejection reason remains unconfirmed.

Deployment and account changes need separate approval. The following configuration
is a reference, not an instruction to change a running service in this review:

```toml
[fido2]
enabled = true
```

FIDO2 is disabled by default. An approved deployment needs Linux's `uhid` module,
access to `/dev/uhid` (packaged module-load/udev rules), an available selected
registration database, a system polkit service and a session authentication agent.
Any compatible polkit agent can be used; [zdr](https://github.com/metalgrid/zdr) is
only an optional authentication example, never a requirement.

The native gate supports one system-bus address: `unix:path=...` or
`unix:abstract=...`, with an optional GUID. Address lists, other transports and
ambiguous keys fail closed. Successful authorization is treated as actual UP and
UV together **only under the shipped fresh `auth_self` authentication assumption**.
Local `yes`, retained/cached authorization, `auth_self_keep`, or agent bypass can
invalidate that assumption. Fake authorization tests are not policy-security
evidence; see [the threat model](threat-model.md).

## Implemented credential and protocol behavior

| Property | Behavior |
|---|---|
| Browser generation | ES256 (COSE -7), ECDSA P-256; `none` attestation |
| Existing local capability | Service/D-Bus generation supports ES256 and EdDSA (-8); signing retains both. Bitwarden import accepts ES256 only |
| Storage | PKCS#8 key, credential ID, exact RP-supplied 1–64-byte user handle and counter in ordinary KeePass entries; new browser entries go to the selected registration database's Passkeys group |
| Identity | Fixed product AAGUID **ab449b5e-d0bf-4d8d-81b1-de5ec1a8c00e** in GetInfo and registration; not vendor certification or hardware attestation |
| Assertion selection | Complete supported allow-list search bound to RP/type/ID; absent/empty lists enumerate discoverable accounts |
| Multiple accounts | `numberOfCredentials` and GetNextAssertion with channel-bound, 30-second continuation state; candidates revalidated on each signature |
| Presence/verification | Standard `up` default true, `uv` independent. Requested checks must succeed; flags report actual checks. Combined native approval can establish both |
| Silent probes | `up=false, uv=false` assertions need no prompt and set neither flag. Required UV is never suppressed by false UP |
| Exclusions | Type/RP/ID-bound; consent before exclusion disclosure; no silent exclusion bypass |
| Account privacy | Opaque user ID returned; identifying names/display names only after actual UV |
| Counters | Persisted on successful signing; exhaustion fails closed, not wraparound. Restoring backups can roll counters back |
| Transport | Strict 64-byte framing, 7,609-byte HID payload ceiling; CTAP advertises 1,024-byte command limit; ownership, timeout, INIT/CANCEL and stale-output suppression |

### Registration replacement and preservation

For explicit resident registration (`rk=true`), a unique complete same-RP/exact
user-ID match is replaced **only in the selected destination**. Any visible match
in another unlocked database or multiple visible matches refuses registration
without mutation. Missing/locked selected destinations fail; there is no arbitrary
fallback. Only unlocked databases are inspected: hidden matches in locked/unopened
vaults do not block registration. Names are not account identity.

Replacement retains the existing entry UUID and original creation time, title,
password, notes, URL, unrelated custom fields, attachments and history. Only
credential fields and normal modification metadata change. False/absent `rk`
and local creation remain append-only; imports remain append-only with duplicate-ID
refusal. There is no schema migration, background rewrite, inferred-handle repair,
automatic unlock or cross-database deletion. Existing keys/IDs/handles remain
unchanged outside explicit eligible replacement and ordinary assertion counters.
External writers use optimistic file-conflict detection, not cross-process locking;
a post-rename save error can mean disk changed despite a failed operation.

### Cancellation limits

CANCEL, timeout, INIT/resync and shutdown cancel native pending work and attempt
`CancelCheckAuthorization` on the same polkit connection. Setup and writes are
bounded by two seconds; cancellation during a stalled dispatch can add up to two
seconds before independently bounded two-second cleanup. Cleanup failure or late
success never approves. An already-entered sink write cannot be recalled, and a
storage write already begun may finish. Cancellation suppresses stale responses,
not completed mutation rollback. The local D-Bus management API has a separate
polkit path; native ceremony cancellation guarantees must not be inferred for it.

## Local APIs and import

`CreatePasskey` and `AssertPasskey` are implemented D-Bus methods, not stubs.
The former creates a local random handle rather than registering a browser's
RP user ID; the latter accepts an explicit clientDataHash and establishes UP,
not the native gate's UV contract. The CLI exposes `passkey list`, `create`,
`remove`, and `import`; there is **no `passkey assert` CLI command**. Local creation
alone does not register a key with a website.

For a separately approved import, the CLI accepts:

```text
kpxcctl passkey import <db-uuid> <bitwarden-export.json> [--dry-run] [--all | --rp=<rpID> | --cred=<credentialID>]
```

It reads decrypted `login.fido2Credentials`, preserving credential ID, user handle,
RP ID and initial counter while converting the P-256 private key. UUID-shaped IDs
use their 16 wire bytes. Exports contain live private keys: protect and dispose of
them under an approved secret-handling procedure. Independent signer copies and
old backups can diverge in counters; do not delete or retire a working copy without
user approval and a verified recovery/sign-in path.

**Transport hints are not local key material.** Original imported registrations
may have server/browser transport hints excluding USB. Local import cannot change
those hints or force a site to offer this native USB authenticator. A site/account
change or re-registration may be necessary, only after approval.

Historical browser registrations created with incorrect random user handles
cannot generally be repaired from local metadata: the RP's original opaque ID is
not recoverable from a username. Only affected credentials may need user-approved
re-registration after preserving a working recovery method. Neither an AAGUID
change nor importing the same key repairs that binding. No bulk re-registration
or Amazon-specific diagnosis/resolution is claimed.

## Remaining limits

- Linux only; no CTAP1/U2F, client PIN, credential management, hybrid/caBLE,
  credProtect, largeBlob or hmac-secret/PRF. Destructive CTAP Reset is not implemented.
- Vault locking makes credentials unavailable and invalidates pending account
  continuation. One approved resident series may return multiple assertions;
  unrelated ceremonies require fresh approval. Silent probes are deliberately
  different from interactive ceremonies.
- Strict CBOR decoder recommendations are recorded separately from mandatory
  requirements in [conformance evidence](fido2-conformance.md).
- Synthetic UHID envelopes are not live kernel tests; fake polkit tests are not
  authentication-policy security evidence. Current browser/live kernel tests
  remain NOT RUN/awaiting approval. No FIDO certification is claimed.
