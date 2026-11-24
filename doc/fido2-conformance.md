# Native FIDO2 conformance evidence

This records the historical red-test foundation and subsequent bounded repairs,
not certification. Steps 1–6 have passing offline regression evidence. Final
independent review is complete; Step 7 live verification remains outstanding. Earlier step
sections/counts are historical, superseded by the final offline summary below.
Existing credentials are not migrated. The approved product
AAGUID is `ab449b5e-d0bf-4d8d-81b1-de5ec1a8c00e`.

## Primary sources

Fetched successfully with `webfetch` during this handoff:

- **C20**: [CTAP 2.0, 2019-01-30](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).
- **W2**: [WebAuthn Level 2, 2021-04-08](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/).
- **C21**: [CTAP 2.1, 2021-06-15](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html).
- **COSE**: [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.html), §§7–8, elliptic-curve keys and algorithms. Successor RFCs 9052/9053 were not fetched in this handoff; no successor-specific conclusions are claimed.

C20 is the advertised contract; C21 §6.4 is relevant to the emitted algorithms
field, not a claim that all CTAP 2.1 features are implemented. Normative field
definitions take precedence over misleading comments or examples. In particular,
GetAssertion options use `up`, not `userPresence`; descriptor and user-entity
maps use text keys. C20 §6 says encoders MUST use canonical CBOR without duplicate
keys, but decoder rejection of noncanonical CBOR and duplicate keys is SHOULD.
The duplicate-key regression deliberately enforces that recommendation rather
than presenting it as a mandatory-conformance failure.

### Corrected anchors verified against primary HTML

- W2 [§6, Authenticator Model](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-model): the AAGUID MUST be identical across substantially identical authenticators and different with high probability from other types; random generation is SHOULD. The fixed UUID is product policy satisfying that model, not a UUID specified by W2.
- W2 [§6.3.4, authenticatorCancel](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel): terminates operations in the authenticator session. §6.4.1 is [String Truncation](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-strings-truncation), not the AAGUID requirement.
- C20 [§5.1, authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential): known options invalid for this command return INVALID_OPTION; implementations MUST understand rk, up and uv. Thus up=true is not an unknown option to ignore.
- C20 [§6, canonical CBOR](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form): duplicate-key rejection is a decoder SHOULD. This remains separately labeled from mandatory failures.

## Requirement/evidence matrix

`H` means `internal/fido2/hid/conformance_test.go`; `HT` means
`internal/fido2/hid/hid_test.go`; `S` means `internal/fido2/service_test.go`.
Rows marked **later** identify tests owned by the specified implementation step,
not missing Step 1 foundation tests. Source inspection is not a passing test.
Step 1 reconstructs the original nine probes and corrects misleading fixtures;
it does not introduce future production interfaces just to test them.

| Finding / acceptance criterion | Primary clause and strength | Affected production code | Permanent evidence |
|---|---|---|---|
| Exact RP user handle survives registration and assertion; 1–64 bytes | C20 §5.1 user parameter; W2 §5.4.3 user handle and §6.3.2 credential creation | `ctap.go` Create, `service.go` CreatePasskey, HID makeCredential | **later, Step 2**: current Create interface drops the handle; do not invent its replacement in Step 1 |
| Standard UP default and explicit false | C20 §5.2 options table (`up` defaults true) | HID getAssertion | HT silent-probe fixture now uses `up`; red |
| UV independent of UP, never silently weakened | C20 §5.2 options and processing; W2 §6.1 flags | HID getAssertion, service SignAssertion | S silent-probe spec now requires UV-without-UP success; red; command-layer combination **later, Step 3** |
| Search entire supplied allow list; enforce RP/type/ID restrictions | C20 §5.2 allowList and credential selection algorithm | HID getAssertion, service SignAssertion | H later allow-list match red; stub now rejects wrong IDs; malformed-list coverage **later, Step 2** |
| Exclusions bound to RP and credential type; required consent before disclosure | C20 §5.1 excludeList and processing algorithm | HID makeCredential, CtapStore HasCredential | H counted approval and denial red (Step 3); existing HT allowGate test remains valid but alone does not check timing; RP/type tests later, Step 2 |
| Multiple resident accounts accessible with numberOfCredentials/GetNextAssertion | C20 §§5.2–5.3, mandatory when multiple matching resident credentials are returned | HID command dispatch, service resident selection | S preserves two accounts without endorsing newest-only selection; wire enumeration **later, Step 5** |
| Replace matching RP/account during approved resident registration | C20 §5.1 resident storage processing; W2 §6.3.2 credential creation | service CreatePasskey | **later, Step 5**, destructive multi-database ownership rule unresolved |
| Required 32-byte registration clientDataHash | C20 §5.1 input table, required parameter | HID makeCredential | H missing-hash red, creation must not occur |
| Validate known option types and command-specific options, fields/descriptors, authentication parameters | C20 §§5.1–5.2 and §6.3 error codes | HID command parsing | H incorrectly typed uv and MakeCredential up=true (0x2c INVALID_OPTION) red; comprehensive lengths/types/PIN combinations later, Step 3 |
| CTAP canonical CBOR, no tags/indefinite lengths; decoder rejection recommendation | C20 §6 Message Encoding | HID decodeRequest | H duplicate keys red (SHOULD); other encodings/depth **later, Step 3** |
| Advertised algorithms match creation support; ES256 COSE representation correct | C21 §6.4 algorithms; C20 §5.1 pubKeyCredParams; RFC8152 §§7–8 | HID getInfoAlgorithms, makeCredential, service key generation | H advertised algorithms red; service signing support must remain intact |
| Stable model identity, not another vendor; config compatibility | W2 §6 Authenticator Model (#sctn-authenticator-model) AAGUID; C20 §5.4 aaguid; UUID choice is approved product policy | HID authdata/GetInfo, service defaults, config | HT decoded AAGUID no longer self-compares; H attested AAGUID red; legacy-config tests **later, Step 6** |
| Continuation sequence and declared lengths correct | C20 §§8.1.4, 8.1.5.4 packet sequencing | HID descriptor encode/decode | H 352/353/1024 sequence; 1001/1002/1024 receive; 353+ and 1002+ red |
| Global ownership includes receive through response transmission | C20 §§8.1.3, 8.1.5.1 atomicity/busy states | HID authenticator | H bounded receive and pending-approval two-channel tests red; transmission/race tests later, Step 4 |
| Validate reserved/unallocated CIDs and standard INIT exceptions | C20 §§8.1.3, 8.1.9.1.3 | HID authenticator | H channel-0 red; remaining CID/INIT cases later, Step 4 |
| Partial-reception timeout releases ownership with protocol error | C20 §8.1.5.2 | HID reassembly/authenticator | **later, Step 4** |
| INIT clears stale reception/work, no stale replies | C20 §§8.1.5.3, 8.1.9.1.3 | HID authenticator | H partial-state clearing red; obsolete work/replies later, Step 4 |
| Cancel current ceremony, no stale keepalive/reply to replacement operation | C20 §8.1.9.1.5 CANCEL and §8.1.9.1.7 KEEPALIVE | HID authenticator/commands | **later, Step 4**; existing cancellation coverage is not complete lifecycle evidence |
| Cancel authorization prompt when ceremony ends; no account-data request dumps | C20 cancellation semantics above; W2 §6.3.4 authenticatorCancel (#sctn-op-cancel); implementation privacy/lifetime requirement | `presence.go`, HID commands | **later, Step 6**: fake authorization-service lifetime test required; no host policy change authorized |
| Counter never wraps into misleading zero | W2 §6.1.1 signature counter considerations (SHOULD increment); refusal at exhaustion is approved fail-closed product policy | service SignAssertion | **later, Step 2**: maximum-counter persistence test needed |
| Probe RP exceptions must not shadow legitimate account semantics | C20 §5.1 and W2 §6.3.2 (no browser-name exception) | CtapStore Create | **later, Step 3**: `.dummy` and `make.me.blink` require standards review, not expanded exceptions |
| Validate response shapes/flags, command lengths and no-argument commands | C20 §§5.1–5.4, §6.3, §8.1.9 | HID commands/authenticator | Existing HT success tests provide partial evidence only; exhaustive invalid-command coverage **later, Step 3** |

## Optional features and exclusions

Client PIN, extensions, CTAP1/U2F, NFC/BLE, credential management, hybrid,
large blobs and PRF are not promised by this repair. Do not advertise unsupported
features. WINK and channel locking are optional (C20 §8.1.9.2). Missing Reset is
recorded separately (C20 §5.6); broad vault deletion is explicitly out of scope,
not implicitly authorized by this matrix. Resident support is advertised, so
multiple-account behavior cannot be dismissed as an unsupported optional feature.
No universal browser compatibility or certification claim follows from unit tests.

## Test construction and isolation

Host reports are now independently constructed with big-endian CID/length and
integer continuation indices. They no longer call the device encoder under test.
CBOR maps are constructed from protocol field definitions using the generic CBOR
library; duplicate-key input is literal bytes, not output of the decoder under
test. Fakes use isolated in-memory credential answers and approval gates; existing
service tests use their isolated temporary database fixtures. No live credentials,
migration, installation or production behavior changes are part of this work.
The old nine-probe temporary directory was absent, so probes were reconstructed,
not copied. All nine behaviors now have permanent specs: outbound sequence,
padding, INIT partial-state clearing, standard up=false, exclusion consent,
later allow-list match, missing registration hash, MakeCredential up=true invalid
option, and duplicate-key decoder SHOULD. Every direct-command authenticator
has a fakeWriter, so delayed gate scheduling/keepalive cannot dereference a nil
sink. The pending-approval contention test observes gate entry, cancels its
one-second context, and waits at most two seconds for operation completion.
No test waits for the production 180-second gate deadline.

## Observed verification

Baseline was independently re-measured from an archive of `815c1fe`, not a
worktree or checkout. Commands (run from the repository unless noted):

```sh
baseline=$(mktemp -d /tmp/kpxcd-step1-baseline.XXXXXX)
git archive 815c1fe | tar -x -C "$baseline"
cd "$baseline"
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -count=1 -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step1-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step1-nonfido-packages) -count=1
```

Archive directory: `/tmp/kpxcd-step1-baseline.wvVlD0`. Baseline FIDO exit 0:
service and HID passed (0.047s and 0.730s). Baseline non-FIDO exit 0:
all ten packages with tests passed; deps, xdg and scripts/mktestdb have no tests.
Logs: `/tmp/kpxcd-step1-baseline-{fido,nonfido}.log`.

Current tree commands:

```sh
gofmt -w internal/fido2/hid/conformance_test.go internal/fido2/service_test.go
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -count=1 -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step1-nonfido-packages) -count=1
```

Current FIDO exit 1, expected red: service 27 passed / 1 failed; HID 23 passed /
19 failed / 3 skipped. Non-FIDO exit 0, all ten tested packages passed.
Logs: `/tmp/kpxcd-step1-current-{fido,nonfido}.log`.
HID failures: sequences 353/1024; padded lengths 1002/1024; duplicate keys;
attested AAGUID; advertised algorithms; missing registration hash; later allow-list
match; INIT clearing; both consent cases; MakeCredential up=true; channel zero;
cross-channel receive and pending approval ownership; known option type;
GetInfo AAGUID; standard silent UP probe. Service failure: UV without UP rejected.

The previous handoff's broad Ginkgo-flag invocation was invalid for standard Go
tests, and its GINKGO_SKIP environment attempt did not reliably skip live tests.
Neither is used as evidence here. These fresh commands explicitly skip all live
UHID specs; no kernel/device tests, daemon restart or host policy changes were run.

## Step 1 task evidence and later test ownership

1. Requirements/corrections/audit mapping: primary references and matrix above.
2. Original probes: all nine reconstructed behaviors listed under construction,
   with independent framing and literal duplicate-key input; current expected-red
   run demonstrates each (some behaviors have multiple boundary specs).
3. Helper corrections: independent buildRequest; ID-sensitive stub; standard up;
   fixed AAGUID expectation; no newest-only endorsement; exact service UP/UV
   assertions; fake writers on all direct command instances; existing allowGate
   exclusion spec preserved alongside counted denial/approval timing checks.
4. Safe baseline: archived 815c1fe FIDO and separate non-FIDO commands passed;
   current targeted run is intentionally red; logs and commands above.

Later tests are explicitly assigned, not unexplained incomplete foundation:
Step 2 owns exact-handle creation/persistence/reload/import preservation, malformed
allow-list restrictions, RP/type exclusions, and counter exhaustion. Step 3 owns
full UP/UV combinations, validation/error ordering, other CBOR encodings/depth,
response shapes and probe exception review. Step 4 owns remaining CID rules,
receive timeout, response-transmission contention, cancellation/resynchronization
and race boundaries. Step 5 owns resident enumeration/GetNextAssertion state,
expiry/locking/reset, and safe same-account replacement. Step 6 owns legacy
configuration compatibility, shared identity and fake authorization cancellation.
No creation or enumeration interface is invented in Step 1, and no reflection
spec is used as a substitute for observable behavior.

## Unresolved design and coverage questions

Same RP/user registrations can exist in several open databases. Which database
owns replacement: configured registration target only, selected database, or all
open databases? What if another database is locked? This handoff makes no choice,
deletes nothing, and adds no migration. Existing keys, IDs and imported handles
must remain unchanged. Counter rollback after restoring an old database remains a
separate documented risk.

At the Step 1 handoff, evidence was ready for parent review, not self-approved
tracker completion. Its changes were intentionally red and must not be relabeled
green by weakening requirements. Steps 2–7 implementation was then untouched.

## Step 2: credential identity and selection

This section supersedes only the Step 2 **later** labels in the historical
matrix; the baseline commands, counts and failures above remain historical evidence.

### Contract and primary-source checks

C20 §§5.1–5.2 were re-fetched. A nonempty allowList restricts assertions to a
denoted credential bound to the request RP. C20 §5.4 explicitly permits resident
lookup when allowList is absent or empty. Malformed supplied lists now return an
error rather than becoming resident lookup. W2 §5.8.3 says client platforms MUST
ignore descriptors with unknown type, and §5.8.2 identifies type as an extension
point. This authenticator likewise does not treat an unknown well-formed text
type as public-key: it ignores that candidate, preserves a nonempty restriction,
and returns NO_CREDENTIALS if no supported candidate matches. Descriptor shape,
required type/ID and nonempty byte ID checks are shared by allow/exclude parsing;
full request/options/CBOR validation remains Step 3.

Browser Create now requires raw userID bytes. CtapStore validates 1–64 bytes and
calls the explicit service CreatePasskeyWithUserHandle path, which base64url
encodes those exact bytes into the existing field. The command boundary checks
presence, byte-string type and 1–64 length. There is no browser random fallback.
The original service CreatePasskey still generates a local handle for the active
D-Bus CreatePasskey method and CLI passkey create. Their public signatures are
unchanged; all creation callers were traced. Existing feature-matrix statements
that these D-Bus methods are unimplemented are stale, not evidence of inactivity;
broad documentation correction remains Step 7.

HasCredential now takes RP plus ID. Command type filtering happens before lookup;
allow-list candidates are checked without signing, and only the first matching
supported candidate is asserted. Exclusion consent/error ordering is deliberately
unchanged: both Step 1 consent probes remain red for Step 3.

### New permanent evidence

`internal/fido2/identity_test.go` uses isolated real KDBX files and actual
CtapStore + service persistence, not a stub Create:

- Exact handles containing embedded zero bytes, a single zero byte, and 64 zero
  bytes survive creation, reopen and assertion. IDs and private/public keys also
  survive reopen unchanged.
- Missing/empty/65-byte browser handles fail without changing database bytes or
  adding entries. Actual store lookup rejects a cross-RP ID without signing or
  advancing its counter.
- Imported IDs, handles, keys and initial counters survive reopen unchanged;
  existing imported credentials assert successfully and increment only their
  counter. Existing local-generation creation/assertion specs are preserved.
- An imported max-uint32 counter refuses assertions on repeated fresh reopens;
  no result is returned and the complete database file remains byte-identical.
- Save-conflict refusal and post-mutation atomic-save failure return no signature
  or created entry and preserve stored credentials/counters. The latter uses an
  open temporary database via /proc/self/fd: fingerprint checks succeed, but
  sibling temporary-file creation fails, exercising existing root rollback.

`internal/fido2/hid/identity_test.go` uses fake approval gates and records Create
input and Assert calls. Cases cover exact 64-byte forwarding, required/type/length
refusals, absent/empty allow lists, malformed array/descriptors/IDs, unknown types,
nonmatches, later matches, and a malformed descriptor after a valid candidate.
Rejected restrictions never reach Assert. Unknown exclude types do not block
creation. The original later-allow-list conformance probe is now green, unchanged.

### Observed verification (Step 2)

```sh
gofmt -w internal/fido2/service.go internal/fido2/ctap.go internal/fido2/hid/gate.go internal/fido2/hid/commands.go internal/fido2/hid/hid_test.go internal/fido2/identity_test.go internal/fido2/hid/identity_test.go
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -count=1 -timeout=60s -ginkgo.focus='Step 2|tries a matching later allow-list credential|round-trips: create, persist, reopen, find, sign, verify|CreatePasskey' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step2-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step2-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Focused Step 2 and local-generation/roundtrip/later-allow-list suites pass.
Full FIDO remains expected-red: service has 38 passed and its one unchanged
UV-without-UP failure; HID has 43 passed, 18 unchanged later-step failures and
three live specs skipped (the previous 19th failure, later allow-list match, is
now green). Non-FIDO/API regression packages pass separately, without Ginkgo
flags. Logs: `/tmp/kpxcd-step2-{focused,fido,nonfido}.log`.

No schema change, bulk rewrite, missing-handle inference, replacement/deletion,
or migration is introduced. Only explicit new registration and successful
assertion perform their ordinary writes. Same-account replacement/multiple
open databases remain Step 5 decisions. AAGUID, independent UP/UV, HID framing
and lifecycle, consent ordering, and broader Steps 3–7 coverage remain as listed
in the historical matrix. No live credentials, UHID devices, host policy,
service restart, deployment, staging or history changes were used.

## Step 3: command validation, independent UP/UV, and capabilities

This section supersedes the Step 3 **later** labels above, not the historical
baseline or Step 2 evidence. The primary C20, W2 and C21 pages were fetched again
and the connected command, adapter, service, gate and test paths were inspected.
No plan/tracker file was changed by this worker.

### Normative decisions and processing order

- **C20 §5.2 options table and final flags table**: `up` defaults true, `uv`
  defaults false, and all four flag combinations have defined meanings. The
  nonstandard `userPresence` key is ignored, not an alias. Neither a false `up`
  nor an unknown option suppresses required verification. `Operation` explicitly
  carries the independently requested presence/verification properties. The
  separate `Approval` result reports approval and actual established UP/UV.
  Commands require approval and every requested property, then report all actual
  checks, including additional checks established by a combined gate. Under the
  shipped fresh-auth `auth_self` policy, successful generic polkit authentication
  establishes both, even for UP-only or UV-only requests. Local policy overrides
  can invalidate this assumption; no authentication method is inferred or required.
  The storage/signing service accepts all four independently established verdicts,
  including UV without UP. Silent requests skip the gate and claim neither.
- **C20 §5.2 processing, “Collect user consent” through “If no credentials”**:
  required consent MUST precede NO_CREDENTIALS disclosure. The former early
  return without a gate was incorrect even though an old fixture endorsed it.
  Read-only lookups can precede consent, but the result is disclosed only after
  requested UP/UV succeeds. Both false is a distinct silent probe and performs
  no gate call. Required UV denial never falls through to silent signing.
  Assertion consent timeout maps to OPERATION_DENIED as this procedure states;
  cancellation/transport ownership remains Step 4.
- **C20 §5.1 processing, first three steps**: a matching type/RP/ID exclusion
  requires presence before CREDENTIAL_EXCLUDED, and denial returns
  OPERATION_DENIED without creation. After full structural validation, that
  exclusion check precedes unsupported-algorithm and invalid-option outcomes.
  The W2 §6.3.2 abstract algorithm checks algorithm support before exclusions;
  this wire implementation follows the advertised C20 command's explicit order.
  W2 §6.3.2's initial syntactic/length validation and exclusion authorization
  rule remain satisfied. Exclusion disclosure asks for UP only; it creates no
  credential and makes no UV success claim.
- **C20 §§5.1–5.2 options processing**: authenticators MUST understand `rk`,
  `up`, `uv`; unknown options are ignored. Known nonboolean values fail type
  validation. MakeCredential `up` (including true) and GetAssertion `rk`
  (including false) return INVALID_OPTION rather than being treated as unknown.
  Supported `rk` does not add migration or replacement semantics in this step.
- **C20 §§5.1–5.2, §6.1; W2 §5.4.3 and §6.3.2**: validate the whole supplied
  request before creation/signing. Missing fields return MISSING_PARAMETER
  (0x14), wrong field/top-level types CBOR_UNEXPECTED_TYPE (0x11), wrong hash,
  user ID, descriptor ID or nonempty PIN-auth lengths INVALID_LENGTH (0x03),
  and empty RP IDs INVALID_PARAMETER (0x02). Both clientDataHash values must be
  exactly 32 bytes; browser user IDs remain byte strings of 1–64 bytes. Required
  RP/user maps, optional known text members, the complete algorithm list and
  complete descriptor lists are validated, even after an eligible candidate.
  Unknown well-formed credential types are not aliases for public-key; unknown
  fields/options are ignored. Optional descriptor transports must be an array
  of strings, but unknown transport strings are tolerated. No credential-ID
  maximum beyond the command size is newly advertised or invented.
- **C20 §§5.1–5.2 authentication steps and §§5.5.8.1–2**: unsupported PIN
  authentication must not downgrade to ordinary signing. Types are validated
  first. A nonempty token requires its protocol companion; an orphan companion
  returns MISSING_PARAMETER. A correctly typed 16-byte token always returns
  PIN_AUTH_INVALID (0x33), including unsupported protocol numbers: no usable
  client PIN/token exists. Other nonzero token lengths return INVALID_LENGTH.
  The specified zero-length `pinAuth` selection probe obtains UP before
  PIN_NOT_SET (0x35), including when no usable protocol was supplied; denial
  returns OPERATION_DENIED without disclosing PIN state. This is not ClientPIN
  implementation or advertisement. There is no PIN retry counter to exhaust.
- **C20 §§6.1–6.3**: GetInfo takes no arguments. Any command-body bytes return
  INVALID_LENGTH, without attempting to interpret a spurious empty map as an
  argument. Oversize commands return REQUEST_TOO_LARGE (0x39). Unknown commands
  and Reset remain INVALID_COMMAND; no destructive Reset is added. The
  command-layer length guard does not replace Step 4's HID framing validation.
  In particular, zero-length CTAPHID_CBOR, INIT/CANCEL lengths, channel ownership,
  and actionable CTAPHID_ERROR replies still belong to transport repair.
- **C20 §6.2 response table** resolves the transposed `fmt`/`authData` labels in
  the §5.1 prose table: MakeCredential returns text `fmt` at 1, bytes authData at
  2, map attStmt at 3; `none` attestation has an empty map. Assertion descriptor
  and user maps use text keys, not the numeric member labels in old comments.
  Only opaque user ID is emitted, never unverified identifying names. Multiple
  account selection and numberOfCredentials/GetNextAssertion remain Step 5.
- **C21 §6.4 algorithms (0x0A)** is an optional generation-capability list,
  nonempty and without duplicates when emitted. It now advertises only ES256.
  The service's existing EdDSA generation/signing and ES256 import support are
  retained, as is the active local D-Bus/CLI generation API. No clientPin,
  pinProtocols or unsupported extension is advertised. Unsupported extension
  inputs are ignored after validating the extension container, as permitted
  by the optional extension-processing steps in C20 §§5.1–5.2.

### Deliberate decoder policy: recommendations are not MUST claims

C20 §6 mandates canonical output without duplicate keys and prohibits tags;
its decoder rejection of noncanonical input and duplicate keys is **SHOULD**.
We deliberately implement that strict input recommendation, rather than silently
accepting malleable representations. This is product policy, not a claim that
permissive decoders necessarily violate a MUST. All output uses the separate
`CTAP2EncOptions` encoder, independently of input validation.

`request.go` configures the existing fxamacker dependency with duplicate-key
detection, tags/indefinite-length rejection, and exactly four supported nested
map/array levels. C20 §6 requires support for at least four and forbids clients
from exceeding four. A bounded header/order walk runs only after the library
has validated a single complete object. It rejects nonminimal integers/lengths
and nonmonotonic map keys without decode/re-encode comparison: CTAP explicitly
preserves floating-point representations, unlike generic shortest-float CBOR
canonicalization. Unknown float values, including NaN payloads, remain accepted.
Complex map keys are outside CTAP's key model and are rejected; noncomparable
array/map keys cannot panic the command parser. Primitive unknown map keys are
still ignored. Large negative integers decode as comparable `*big.Int` values
using the existing library's `BigIntDecodePointer` option; canonical wire-order
validation independently rejects duplicate keys even when pointer identities
would differ. No custom general CBOR decoder is introduced. Malformed encoding,
duplicate keys, tags, indefinite values,
noncanonical representations, invalid UTF-8, excessive nesting and trailing
objects return INVALID_CBOR (0x12). A well-formed non-map top level instead
returns CBOR_UNEXPECTED_TYPE. Integer normalization does not narrow an unknown
uint64 key into a known command key. No dependency was added.

Context7 `/fxamacker/cbor` DecOptions and CTAP2EncOptions documentation was checked
against the installed API. Ordinary test host requests now use a separately
configured canonical encoder instead of randomized default map encoding. Raw
hex fixtures—not marshaled maps—pin the strict rejection and acceptance policy,
including float16/32/64, NaN, four/five nesting levels, byte-string map keys,
large unsigned keys, malformed top levels and noncomparable keys. These fixture
changes preserve the Step 1/2 behaviors and all future-step red expectations.

### Chromium RP exceptions

C20 §5.1 requires a usable credential key pair and RP/account association;
W2 §6.3.2 requires a retrievable public key credential source (persisted for
client-side discoverable credentials, or recoverably encrypted in its ID).
Neither standard reserves `.dummy` or `make.me.blink` for disposable credentials.
The old adapter returned a random ID and public key while discarding its private
key, making a nominally successful registration impossible to assert later.
The `make.me.blink` name can also denote an ordinary RP. Both special creation
branches and command-layer browser-probe routing/logging were removed: RP IDs
are opaque here and receive normal persistence, RP binding and assertion
behavior. No new browser-specific branch or claim about a browser's current
probe behavior is introduced. This deliberately means successful probe-like
registrations can be stored; deletion/replacement is not silently invented.
The new service tests create, reopen and assert credentials for both RP IDs,
checking exact handles, keys and cross-RP refusal in isolated databases.

### Five task evidence and observed verification

1. Independent UP/UV: `hid/validation_test.go` covers defaults, explicit four
   combinations, exact Operation values/counts, exact returned flags, denial,
   silent probes and ignored userPresence; `fido2/validation_test.go` exercises
   all four service combinations. The unchanged Step 1 UV-without-UP spec is green.
2. Fields/authentication: registration/assertion refusal tables cover required,
   type and length distinctions, whole-list validation, optional members,
   options/extensions and authentication combinations; malformed requests do
   not gate, create or sign. Registration approval/refusal checks exact flags.
3. Consent/error order: both unchanged counted exclusion probes are green;
   additional tests cover exclusion-before-algorithm/options, no-credential
   privacy, silent no-credential lookup and zero-length PIN-probe denial.
4. Decoder: literal wire fixture tables cover the policies above, with safe
   rejection before store use, not only a duplicate-key marshaled-map test.
5. Capabilities/responses/exceptions: independent GetInfo shape/canonical checks
   and ES256-only baseline are green; normal RP persistence tests cover both
   formerly special names. Fixed AAGUID tests are deliberately still red.

Commands (all output captured, no live transport access):

```sh
gofmt -w internal/fido2/{ctap.go,service.go,validation_test.go} internal/fido2/hid/{authdata.go,authenticator.go,commands.go,gate.go,request.go,validation_test.go,hid_test.go,identity_test.go,conformance_test.go,live_test.go}
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.focus='Step 3|Step 2|does not disclose an excluded|requires clientDataHash|rejects the known up|rejects incorrectly typed|advertises only|rejects duplicate|signs silently|signs with UV independently' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step3-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step3-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Focused exit 0: service **18 passed**, HID **142 passed**, no failures (the focus
filter skips unrelated specs). Full FIDO exit 1 only for future-step failures:
service **45 passed / 0 failed**; HID **166 passed / 10 failed / 3 live skipped**.
The ten unchanged future-step failures are outbound continuation 353/1024,
padded receive 1002/1024, INIT partial-state clearing, reserved channel zero,
cross-channel receive ownership, pending-approval ownership (Step 4), and the
GetInfo/attested AAGUID expectations (Step 6). No future-step failure was removed
or weakened. Separate non-FIDO exit 0: all ten packages with tests passed, three
packages had no tests; these commands used no Ginkgo-only flags. Diff whitespace
checks passed. Logs: `/tmp/kpxcd-step3-{focused,fido,nonfido}.log`.

Fake approval tests establish control-flow and flags only. They do not prove
live polkit security, fresh authentication under local policy, browser
compatibility, or certification. Outstanding polkit-call cancellation and
identity/configuration remain Step 6; the shipped-policy assumption is now explicit
in the gate result contract, without live-policy verification. No live UHID test, daemon restart, live
credential operation, migration/replacement/deletion, host policy change,
deployment, staging, commit, push, tag or worktree operation was performed.

### Step 3 review corrections (2026-11-16)

The earlier observed counts remain historical baselines, not proof of the
subsequently identified gate-contract and primitive-key boundary defects.
`Gate.Approve` now returns `Approval{Approved, UserPresence, UserVerification}`.
`waitGate` discards the complete result on denial, cancellation, deadline, or
missing requested checks. Consent returns only sufficient actual results;
registration flags and assertion signing use these actual properties, never
request bits. The production gate reports both properties on successful
fresh-auth authorization under the shipped `auth_self` policy, not merely the
requested subset. This is an explicit deployment-policy assumption, not a new
live security claim. Errors and cancellation return the zero verdict. Active
D-Bus APIs and the service's four independent verdict combinations are unchanged.
Outstanding interactive polkit-call cancellation is deliberately not repaired here.

`BigIntDecodePointer` is the focused decoder representation correction for valid
negative primitive keys below MinInt64. Literal fixture
`a21863003bffffffffffffffff00` now succeeds. Independent actual-command wire
fixtures prove that this key is ignored without concealing malformed known
fields. Additional literal tests cover positive/negative int64 boundaries,
uint64 extremes, nested negative keys, distinct text/integer keys, duplicate
large-negative keys, nonminimal aliases, truncation and single-byte panic safety.
The existing strict CBOR and float-width/NaN fixture policies remain green.
No general decoder, dependency, or known-field validation bypass was added.

`hid/approval_test.go` additionally covers combined actual results for UP-only
and UV-only requests, registration flags, silent gate bypass, approved but
incomplete results, denied partial results, and canceled successful late results.
Existing fake gates now return explicit actual verdicts; the command never
manufactures a verdict from the requested checks.

Repeated the exact focused/full FIDO commands above with
`GOEXPERIMENT=runtimesecret`, `-count=1`, `-timeout=60s`, and explicit
`-ginkgo.skip='live uhid transport'`. Focused exit 0: service **18 passed**,
HID **165 passed**, zero failures. Full FIDO exit 1: service **45 passed**;
HID **189 passed / 10 failed / 3 live skipped**. The same eight Step 4 HID and
two Step 6 AAGUID failures remain; no new failure was introduced. Separate
non-FIDO regressions, without Ginkgo flags, passed all ten tested packages
(three packages have no tests). Changed Go files were gofmt'd; `git diff --check`
passed. Logs: `/tmp/kpxcd-step3-correction-{focused,fido,nonfido}.log`.
No plan/tracker edits, live transport tests, deployment, restart, host-policy
changes, live credential operations, or Git writes were performed.

## Step 4: HID framing and transaction lifecycle (2026-11-16)

This section supersedes the Step 4 **later** labels, preserving the historical
red evidence above. C20 was fetched again from the primary source. The six
transport tasks are implemented without resident replacement/GetNextAssertion,
destructive Reset, AAGUID/config changes, or a polkit cancellation overhaul.

### Primary clauses and explicit transport choices

- C20 [§8.1.4, message/packet structure](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure)
  defines fixed-size packets, 57 initial data bytes, 59 continuation bytes,
  sequences 0–127, and the 7,609-byte framing ceiling for 64-byte reports.
  Continuation arithmetic now divides before byte narrowing. Assembly consumes
  only the remaining declared bytes, ignoring even nonzero final padding.
  Zero-length PING is valid. A 7,610-byte declared message is INVALID_LEN, not
  TIMEOUT. Short/long reports are not silently zero-padded or truncated; an
  addressable malformed report receives INVALID_LEN. Fewer than four bytes
  cannot identify a response CID and are dropped. The UHID bridge strips only
  an exact 65-byte report with a zero report-ID prefix, preserving every other
  actual length for validation.
- C20 [§6, message encoding](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding),
  [§5.4 GetInfo](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo),
  and §6.1 distinguish the CTAP message limit from HID framing. GetInfo still
  advertises 1,024 bytes, including the one-byte CTAP command. HID PING supports
  the whole 7,609-byte framing range. A complete CBOR command above 1,024 bytes
  returns CTAP REQUEST_TOO_LARGE (0x39), not a HID timeout or truncated command.
- C20 [§8.1.3, channels](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-channels)
  reserves zero and broadcast. Ordinary initial packets require an allocated
  CID; only broadcast INIT allocates channel state. Unallocated INIT does not
  allocate implicitly. Invalid channels return INVALID_CHANNEL (0x0b), except
  spurious continuations and inactive CANCEL as specifically required below.
  Allocated IDs remain unique for this device lifetime; exhaustion refuses
  allocation rather than wrapping into a reserved or existing ID.
- C20 [§8.1.5.1, atomicity](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-transactions)
  locks the device from the first accepted initial packet through the final
  response packet. One operation identity owns reception, approval, execution,
  queued response and actual transmission. Other channels get CHANNEL_BUSY
  (0x06); a new ordinary initial packet on the owning CID also gets busy rather
  than replacing its request. Broadcast INIT is not exempt from cross-channel
  arbitration. Approval and KEEPALIVE do not release ownership.
- C20 [§8.1.5.2, timeout](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-transaction-timeout)
  requires stalled reception to back out but specifies no numeric HID timeout.
  **Product policy:** a 500ms inter-packet receive timeout. Every timer carries
  the exact operation and receive-progress generation, so a stopped timer's
  already-running callback cannot expire later progress or another request.
  Timeout returns MSG_TIMEOUT (0x05), invalid continuation sequence returns
  INVALID_SEQ (0x04), and malformed addressable reports return INVALID_LEN
  (0x03). These abort partial reception; its old continuations cannot execute.
  [§8.1.5.4](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-packet-sequencing)
  specifically says spurious continuations without an initial packet are
  ignored, including on a nonreceiving CID. No receive state is allocated for
  these packets or arbitrary unallocated CIDs.
- C20 [§8.1.5.3, resynchronization](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-transaction-abort)
  and [§8.1.9.1.3 INIT](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-init)
  make same-active-CID INIT the abort exception. Its payload must be eight
  bytes. Valid resync discards reception, pending same-CID output, and operation
  state, cancels the old context, and echoes the nonce and same CID on that CID.
  Idle broadcast INIT echoes the nonce on broadcast with a newly allocated CID.
  Repeated INIT never retains executable old reception or queued old replies.
- C20 [§8.1.9.1.5 CANCEL](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-cancel)
  is the other transaction exception. BCNT must be zero. It cancels only an
  actively processing CBOR request on the same CID, never a different CID,
  partial receive or already-final response. Inactive CANCEL (including a
  reserved/unallocated CID) is ignored by the explicit SHALL-ignore rule.
  Malformed CANCEL is ignored and does not cancel: the command MUST NOT itself
  receive a response. Only the canceled operation can return CBOR
  KEEPALIVE_CANCEL (0x2d), not a HID ERROR; subsequent INIT invalidates even that
  pending completion. A later transaction cannot inherit its cancellation flag.
- C20 [§8.1.9.1.6 ERROR](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-error)
  supplies the exact error bytes; OTHER is 0x7f, not LOCK_REQUIRED 0x0a.
  [§8.1.9.1.2 CBOR](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-cbor)
  permits keepalives before the final CBOR response; §8.1.9.1.7 explicitly says
  they do not finish a transaction (its opening MSG wording is not a prohibition
  on the CBOR behavior just specified). Pending approval reports UPNEEDED at
  100ms intervals. INIT capabilities remain CBOR|NMSG: MSG, optional WINK/LOCK,
  host ERROR/KEEPALIVE and unknown commands receive INVALID_CMD, not silent
  acceptance or invented optional functionality. Empty HID CBOR is INVALID_LEN.

### Lifecycle and independent evidence

`authenticator.go` uses one explicit operation pointer as the generation token,
with a bounded output FIFO and one complete-message writer. The pending queue
holds at most 16 messages; keepalives coalesce, obsolete owned output is pruned,
and resync drops buffered same-CID replies/errors. A stalled sink plus a host
flood exceeding that queue fails the transport closed rather than allocating
unbounded output or interleaving reports. This is an implementation resource
policy, not a CTAP-prescribed queue size. Reception remains responsive to INIT
and CANCEL while output is blocked, including behind a queued busy error.
The state mutex is never held while writing or waiting for approval. The writer
checks operation identity before each report and releases ownership only after
its final write succeeds or fails. A keepalive write failure aborts its operation.

An already-entered sink write cannot be recalled. Resync suppresses all remaining
old fragments and its reply follows that one report; no old output follows the
INIT reply. Likewise a store call already begun may finish persistence: tests
prove its obsolete signature is suppressed, not that transport rolls storage
back. Cancellation contexts still reach the existing production Gate and polkit
path. Approval properties, fail-closed sufficiency, independent UP/UV, canonical
CBOR and exact Step 2 identities are preserved. Step 6 still owns outstanding
polkit-call cancellation and the two deliberately red AAGUID expectations.

`transport_test.go` adds 49 Ginkgo specs using fake sinks/gates and no kernel:
independent host framing at 0/57/58/116/117/352/353/1001/1002/1024/7609,
literal 7610 overflow, final sequence 127, CTAP-overlimit refusal, nonzero
padding, truncated reception, malformed reports, invalid CIDs, command lengths,
unsupported capabilities, nonce/allocation semantics, sequence/timeout cleanup,
obsolete timer callbacks, same/different-CID contention, blocked/failed output,
receive-loop responsiveness, bounded-output flooding, coalesced keepalives,
100 repeated resyncs behind a blocked writer, shutdown, cancellation races,
late successful approval and late store signatures. Host packets/expected
continuations never come from the production encoder.

The eight original Step 4 probes now pass with their expected behavior intact.
As output is asynchronous, three old wire-error probes now wait at most one
second for the exact same error; the INIT probe's map assertions take the state
mutex. The test allocator previously read nonce bytes at report offsets 8–11
instead of the returned CID at 15–18; it now uses the actual allocated CID.
The CBOR reply helper waits for complete independently counted fragmentation
before reconstructing a response instead of racing the first report.

### Observed verification (Step 4)

```sh
gofmt -w internal/fido2/hid/{descriptor.go,authenticator.go,commands.go,hid_test.go,conformance_test.go,transport_test.go}
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/hid -v -count=1 -timeout=60s -ginkgo.focus='Step 4' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test -race ./internal/fido2/hid -v -count=1 -timeout=120s -ginkgo.focus='Step 4|CTAPHID_CANCEL|keeps receive ownership|keeps approval ownership|discards partial reception|rejects reserved channel zero' -ginkgo.skip='live uhid transport'
# The preceding race command was also run separately with -ginkgo.seed=11, 12, 13.
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step4-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step4-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Full FIDO exits 1 only for Step 6: service **45 passed / 0 failed**; HID
**246 passed / 2 failed / 3 live skipped**. The two failures are the unchanged
GetInfo and attested AAGUID expectations. Focused Step 4 exits 0: **49 passed**.
Focused transport race exits 0: **55 passed**, no race reports, including all
three separate fixed-seed reruns. Focus filters additionally skip unrelated specs.
Non-FIDO suites exit 0: all ten tested packages passed, three have no tests;
no Ginkgo flags were passed to these packages. Formatting and diff whitespace
checks pass. Logs: `/tmp/kpxcd-step4-{focused,fido,nonfido,race}.log` and
`/tmp/kpxcd-step4-race-{11,12,13}.log`.

The first race pass exposed an unsynchronized old test map assertion, fixed by
locking that assertion rather than weakening its expected state. Attempts to
repeat with `go test -count=5` and `-ginkgo.repeat=4` were rejected by the installed
Ginkgo runner; only separate `-count=1` invocations are claimed as race evidence.
No live UHID access, deployment/restart, live credential or host-policy change,
plan/tracker edit, nested delegation, Git write/staging/commit/push/tag/worktree
operation was performed. This is bounded transport evidence, not certification.

### Step 4 correction: production UHID receive envelope

Independent review found that the preceding tests bypassed the production
receive adapter. Their passing results did not establish that real kernel
Output events reached framing: Start cloned the entire padded union as a report.
This section corrects that gap; all preceding counts remain historical evidence.

Inspected the pinned `vendor/github.com/psanford/uhid/uhid.go` and local
`/usr/include/linux/uhid.h`. The library reads 4,380 bytes and dispatches
`Event.Data = buf[4:]` (4,376 bytes). Linux's packed `uhid_output_req` has
`data[4096]`, `size` (uint16) at union offsets 4096–4097, and `rtype` (uint8)
at 4098. UHID_OUTPUT_REPORT is 1 (FEATURE=0, INPUT=2). `parseUHIDOutput`, now
called by Start, requires all 4,099 bytes of that member, decodes size using the
pinned library's little-endian convention, and copies only the declared data.
The remaining union padding is never report data. No vendor or dependency changed.

Zero or greater-than-4096 size, truncated member, wrong rtype, and an exact
65-byte report with a nonzero ID are dropped with a fixed, metadata-only error;
there is no trustworthy CTAPHID CID to answer. No report/account bytes are logged.
The descriptor has no Report ID items: exactly 65 declared bytes with a zero
prefix are accepted as the optional hidraw no-ID representation and normalized
to 64. This is a compatibility allowance, not a new numbered-report descriptor
or a live browser claim. All other lengths remain intact, including 1, 3, 63,
66 and 4096; existing strict handleReport rules decide addressability and
INVALID_LEN. Returned storage is cloned before crossing the event channel.
Malformed envelopes do not alter transaction state; existing receive timers
remain responsible for incomplete transactions.

`uhid_output_test.go` adds **23 synthetic specs** exercising this same parser,
not a test-only decoder. Fixtures use literal offsets 4096/4097/4098, nonzero
full 4,376-byte union padding, independent declared sizes and report bytes.
Coverage includes 64/65 zero-ID, nonzero ID, zero/max/overmax size, truncated
metadata, FEATURE/INPUT/unknown type, copied storage, and preserved short/long
lengths. Both valid padded INIT forms pass through the adapter into real
handleReport and produce independently checked broadcast INIT framing, nonce,
and allocated CID. Short/long/max reports reach real framing and return
INVALID_LEN without silent truncation. No kernel device is used.

Verification (all uncached, `GOEXPERIMENT=runtimesecret`):

```sh
gofmt -w internal/fido2/hid/{authenticator.go,uhid_output_test.go}
GOEXPERIMENT=runtimesecret go test ./internal/fido2/hid -v -count=1 -timeout=60s -ginkgo.focus='Step 4' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test -race ./internal/fido2/hid -v -count=1 -timeout=120s -ginkgo.focus='Step 4|CTAPHID_CANCEL|keeps receive ownership|keeps approval ownership|discards partial reception|rejects reserved channel zero' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step4-adapter-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step4-adapter-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Focused Step 4: **72 passed / 0 failed / 202 focus-skipped**. Full FIDO:
service **45 passed / 0 failed**; HID **269 passed / 2 failed / 3 live skipped**.
Only the existing GetInfo and attested AAGUID expectations fail (Step 6).
Focused transport race: **78 passed / 0 failed / 196 focus-skipped**, no race
reports. Separate non-FIDO: **ten tested packages passed**, three without tests.
Logs: `/tmp/kpxcd-step4-adapter-{focused,fido,race,nonfido}.log`.
Formatting and diff whitespace checks passed. No plan/tracker edits, nested
delegation, Git writes, deployment/restart, policy changes, live credentials,
or live UHID tests occurred. Steps 5/6 remain outside this correction.

## Step 5: resident accounts and bounded continuation

This section supersedes the historical Step 5 **later/unresolved** labels above.
The earlier measurements and ownership questions remain historical records, not
current policy. C20 §§5.1–5.4 and §6.2 were fetched and checked again.

### Normative behavior and selected ownership policy

- **C20 §5.1, processing step “If rk in options parameter is set to true”**:
  overwrite an existing credential with the same RP ID and account ID and store
  the user parameter with the new key. `rk` defaults false. The wire Create
  contract now carries the actual resident intent; overwrite is performed only
  for explicit `rk=true`. Absent/false `rk` registrations retain append behavior.
  KeePass credentials remain physically resident/discoverable, as before; false
  does not promise stateless wrapped credentials or a new nonresident capability.
  The local service/D-Bus/CLI CreatePasskey contract still generates a random
  handle and appends. CreatePasskeyWithUserHandle also retains append semantics;
  the CTAP adapter explicitly selects the approved registration path.
- **User-selected policy, not a CTAP multi-file rule**: inspect unlocked databases
  only. A unique complete same-RP/exact decoded user.id match may be replaced only
  in the selected registration destination. Any visible match in another unlocked
  database, or multiple visible matches anywhere, refuses the registration without
  mutation. Names/display names are never identity. Partial matching credential
  data fails closed, not inferred repair. No cross-database migration or deletion
  occurs. An unrelated known locked database does not block registration.
- A configured/explicit destination must be available. CtapStore compares paths
  with the existing XDG/config expansion plus lexical cleaning; it never falls
  back to map-ordered pool.List()[0]. The daemon's existing deterministic default
  (explicit default, otherwise first configured database) remains its selection
  policy. No new configuration modes, selection UI, unlock prompts or symlink
  discovery are introduced. Availability is checked again during mutation.
- **Accepted visibility limit**: matches hidden in locked or unopened databases
  cannot be discovered, and do not prevent registration. No automatic unlock,
  historical-handle correction, name-based identity inference or background
  migration is performed. Imports remain append-only and retain their own
  duplicate-ID refusal. Imported keys/IDs/handles outside an explicitly eligible
  replacement are unchanged.
- Replacement updates credential fields in the existing entry, preserving its
  UUID, original entry creation time, title, password, notes, URL, unrelated
  custom fields, attachments and history. Last-modification time changes normally.
  New credentials store explicit `KPXCD_PASSKEY_DISPLAY_NAME` and
  `KPXCD_PASSKEY_CREATED` fields. The latter separates credential creation from
  the age of an imported KeePass login; replacement does not rewrite the login's
  original creation time. Existing entries are not rewritten or migrated.
- **C20 §5.2, selection steps after consent**: a nonempty allow list selects any
  eligible denoted credential without exposing other resident accounts. Absent or
  empty allow lists enumerate resident accounts newest-created first. Explicit
  credential creation time is used when present; legacy entries use their entry
  creation time, missing times sort oldest, and database/entry UUIDs break ties
  deterministically. More than one account returns numberOfCredentials at key 5;
  single-account responses omit this optional count.
- **C20 §5.2 user response and processing; §6.2 response keys**: every resident
  response includes the actual opaque user.id. Identifying name/displayName
  members appear only after actual UV, not merely requested UV or approval.
  Display names are never inferred from entry titles. Both service and command
  layers enforce the privacy boundary. All output retains canonical CBOR.
- **C20 §5.3**: GetNextAssertion is command 0x08 and takes no arguments. Missing,
  exhausted, invalidated or greater-than-30-second-old state returns NOT_ALLOWED
  (0x30). Successful continuation resets the timer and increments the account
  cursor; failures do neither and clear state. Continuations omit the count.
  Argument bytes return INVALID_LENGTH and clear continuation authorization.

### Storage consistency and HID lifecycle

Fido2Service serializes FIDO creation, import, removal and signing with one
service mutation mutex. DatabasePool.WithUnlockedDatabases holds the pool read
lock across the membership/availability inspection and selected save; pool
lifecycle takes the pool lock before database locks. Its callback must not call
pool methods. It is not a cross-file transaction or an event subsystem. Resident
replacement has exactly one UpdateAndSave callback/save, validates before any
mutation, and never deletes a whole entry. Arbitrary external file writers remain
subject to existing optimistic fingerprint conflict detection, not a distributed
transaction guarantee.

Pending HID state contains only the original RP/hash, actual approval verdicts,
account cursor/time and candidate identifiers: database UUID **and open-instance
ID**, entry UUID, RP, credential ID and handle. It contains no private keys or
cached PasskeyEntry. Each continuation directly re-enumerates and checks the
original account set, including already returned accounts, so lock, reopen,
removal or replacement invalidates it even if pool events were dropped. No event
forwarding is required. The targeted service call then revalidates the selected
identity inside the same UpdateAndSave callback that reads its current key,
signs and advances the counter. Pool membership/open-instance stability covers
that save. There is no fallback to another database's same credential ID. Invalid
identity, exhausted counters and failed saves return no signature; validation and
signing errors occur before counter mutation.

One operation generation and the CID bind continuation authorization. Ordinary
successful final-response completion preserves it. Accepted INIT/resync, unrelated
CTAP/HID commands, cancellation of active CBOR work, close, actionable receive
failure/timeout or failed owned output clear it. Inactive/non-active-CID CANCEL
remains ignored as C20 §8.1.9.1.5 requires. A different CID cannot continue the
series. Stale work cannot restore state after resync, and approval is never reused
for a new GetAssertion or registration. The existing single-writer ownership,
keepalive and UHID-envelope adapter remain intact.

Save-failure testing found a relevant pre-existing rollback defect: the library's
Entry.Clone/Group.Clone generate fresh UUIDs. Rollback snapshots now restore the
original group/entry/history UUIDs, rather than changing in-memory identities
following a failed save. Snapshot readers likewise retain entry UUIDs and copy
mutable entry slices under the database lock. The existing root rollback behavior
is retained on save errors. **A post-rename error can still mean disk changed**;
no unchanged-disk or rollback guarantee is made for that uncertain outcome.
The tested atomic-save failure uses /proc/self/fd and fails before rename.

### Permanent evidence and observed verification

`internal/fido2/resident_test.go` adds **30 isolated real-KDBX specs**: exact decoded
identity (including alternate trailing base64 bits), name-only/wrong-RP nonmatches,
unique replacement with unrelated fields and entry age preserved, same-file and
cross-file ambiguity, locked unrelated vaults/hidden-match limitation, selected
locked/missing/empty destinations, path cleaning, append-only false-rk/imports,
import preservation, pre-mutation conflicts, post-mutation/pre-rename save failure
with identity rollback, concurrent resident registrations, concurrent imports,
newest ordering/deterministic ties, lock/reopen/new instance, replacement/removal,
RP/ID/handle changes, duplicate-ID cross-file no-fallback, exhaustion, concurrent
targeted signing/replacement and actual-UV privacy.

`internal/fido2/hid/resident_test.go` adds **28 fake-store/gate/writer specs**:
three selectable accounts, one approval, original hash reuse, count placement,
exhaustion, single/empty/nonempty allow lists, actual-UV names privacy, expiry and
successful timer reset, disappearing original candidates, authoritative targeted
refusal, CID binding, no-argument validation, unrelated CTAP commands, fresh
approval on new requests, persistence across ordinary wire completion, INIT/PING,
close, cancellation/resync during a slow continuation, and true/false/absent rk
forwarding. Existing stub overrides were adapted so earlier selection, approval
and operation-generation tests still exercise their original checks.

Commands (all uncached; no live device or account access):

```sh
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.focus='Step 5' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test -race ./internal/fido2/... -v -count=1 -timeout=180s -ginkgo.focus='Step 5|Step 4|CTAPHID_CANCEL|keeps receive ownership|keeps approval ownership|discards partial reception|rejects reserved channel zero' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step5-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step5-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Focused Step 5: service **30 passed / 45 focus-skipped**; HID **28 passed /
274 focus-skipped**. Full FIDO: service **75 passed / 0 failed**; HID **297 passed /
2 expected AAGUID failures / 3 live skipped**. Focused Step 5/transport race:
service **30 passed / 45 focus-skipped**; HID **106 passed / 196 focus-skipped**,
no race reports. Separate non-FIDO suites: **ten tested packages passed**, three
without tests; no Ginkgo flags were passed. Logs:
`/tmp/kpxcd-step5-{focused,fido,race,nonfido}.log`. Changed Go files were gofmt'd;
diff whitespace checks passed.

Only Step 5 was implemented. The two Step 6 product-AAGUID tests remain red;
AAGUID, polkit cancellation, legacy configuration and deployment remain untouched.
No plan/tracker edit, nested delegation, staging/commit/push/tag/worktree write,
service restart, host-policy change, live credential or UHID test was performed.
These isolated results are not FIDO certification or a live browser claim.

### Step 5 concurrency correction: exact destination and atomic ownership check

Independent review found two gaps in the preceding storage-consistency claims.
Those earlier passing measurements remain historical evidence, not evidence for
these interleavings: resolving the configured path to a UUID allowed a copied
vault's same-UUID Open to redirect creation, and pool membership stability alone
did not stop Secret Service attributes changing between per-database snapshots
and the target save. The service mutation mutex never covered those writers.

`CtapStore.defaultDB` now returns the selected `*dbpool.OpenDatabase`, not just
its root UUID. Internal `createPasskey` carries that pointer through key generation
and persistence. Under the pool read lock, the save boundary requires the pool's
current UUID member to be that exact pointer. Copied-path replacement and reopening
the same path both invalidate the selection; no UUID-only re-resolution occurs.
Public CreatePasskey/CreatePasskeyWithUserHandle and D-Bus/CLI signatures remain
unchanged and append-only. They resolve their supplied UUID once to an instance.

`DatabasePool.UpdateAndSaveWithUnlockedDatabases` owns the complete locking
boundary; callers do not acquire/release locks or request a caller-controlled
"already locked" mode. Lock order is:

1. Existing FIDO service mutation mutex, where applicable.
2. Pool read lock, retaining membership and lifecycle stability.
3. Database content locks in ascending immutable open `InstanceID` order:
   write lock on the selected target, read locks on other members.
4. Availability filtering, ownership scan, validation, target mutation and its
   one save all occur before those content locks are released in reverse order.

The callback receives unlocked contents only, must treat non-target databases as
read-only, and must not reenter pool/database lock-taking methods. The private
`updateAndSaveLocked` helper shares the existing UpdateAndSave fingerprint,
root-snapshot, save and rollback implementation; it is not a new public locking
primitive. Other database readers remain concurrent under the read locks. Locked
members' contents are not scanned, and they do not cause policy refusal. No second
database is mutated. An independent writer that acquires its lock after registration
completes is allowed, even if it introduces a later duplicate; there is no retroactive
refusal or cross-file transaction claim.

Audit of production content writers found that all use the same database write
mutex: FIDO local/browser creation, import, removal, ordinary counter advance and
targeted resident signing; Secret Service CreateItem (including replacement and
arbitrary attributes), Item.Delete, Item.SetSecret, and item-property Label and
Attributes setters; and D-Bus SshGenerateKey/SshImportKey. UpdateAndSave and Save
both take that mutex. No production caller uses OpenDatabase.Lock to mutate
outside those paths. Pool Open replaces membership under its write lock; Lock,
LockAll and Close follow pool-before-database ordering. Existing callback bodies
were checked for pool/database reentry; no writer adapter needed a new lock or
signature change. Thus an attribute writer cannot finish inside the ownership
check/save gap, irrespective of the FIDO service instance used.

New isolated evidence:

- Six new resident-storage specs cover stale selection after copied-path or
  same-path reopening; an independently completed UpdateAndSave writer causing
  same-file or cross-file ambiguity refusal; and concurrent same-account creation
  through separate service instances with the same or different target databases.
  Different-target contention yields exactly one successful registration and one
  ownership refusal, with one resident account left visible.
- Seven new dbpool specs directly exercise the shared boundary: target/other
  attribute writers paired with concurrent pool Lock/Open; direct same-UUID Open
  displacement while the selected instance is still unlocked (copied and same
  paths); and whole-tree UUID rollback after a post-mutation/pre-rename failure.
  The gap tests wait for callback entry, use TryLock to prove exclusion of both
  content writers and pool lifecycle, prove unrelated read-lock access, and hold
  release channels while separately started writers cannot enter/finish. Completion
  after release is bounded. No sleep-based ordering or production timing hook is
  used. Displaced fixture watchers are explicitly cleaned up.
- Rollback evidence compares independently marshaled original/restored root XML,
  including nested groups, unrelated entries, histories and nested history entry
  UUIDs; it does not use the clone-under-test as its expected-value oracle.
- The two targeted resident privacy cases now verify ECDSA/ASN.1 signatures over
  the returned authenticator data and original clientDataHash using the stored
  credential's public key, instead of accepting a nonempty signature alone.

The policy and limitations above are unchanged: unlocked/visible databases only,
selected-database-only replacement, no inferred legacy repair, and optimistic
external-file conflict detection rather than exclusion of external processes.
The existing post-rename uncertain-save limitation remains. No Step 6 identity,
configuration or polkit work is part of this correction.

Correction verification (all uncached, `GOEXPERIMENT=runtimesecret`):

```sh
go test ./internal/dbpool ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.focus='Step 5|UpdateAndSave' -ginkgo.skip='live uhid transport'
go test ./internal/dbpool -v -count=1 -timeout=60s
go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
go test -race ./internal/dbpool ./internal/fido2/... -v -count=1 -timeout=180s -ginkgo.focus='Step 5|UpdateAndSave' -ginkgo.skip='live uhid transport'
# Non-FIDO packages were listed separately and tested without Ginkgo flags.
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step5-correction-nonfido-packages
go test $(< /tmp/kpxcd-step5-correction-nonfido-packages) -count=1 -timeout=60s
```

Focused: **9 dbpool, 36 service, 28 HID passed**. Full dbpool: **21 passed**.
Full FIDO: **81 service passed**; HID **297 passed, 2 expected Step 6 AAGUID
failures, 3 live skipped** (GetInfo and attested product AAGUID remain unchanged).
Focused race: **9 dbpool, 36 service, 28 HID passed**, no race reports. Separate
non-FIDO: **ten tested packages passed**, three without tests. Logs are
`/tmp/kpxcd-step5-correction-{focused,dbpool,fido,race,nonfido}.log`.
Changed Go files were gofmt'd and diff whitespace checks passed. No plan/tracker
edit, nested delegation, dependency addition, Git write, deployment/restart,
policy change, live vault/device access or Step 6 work occurred.

### Step 5 connected-path correction: Secret Service enumeration

The preceding results remain historical: they did not exercise Collection.Items
holding an outer database reader while itemsForCollection acquired another.
A queued registration writer blocks that inner reader under Go RWMutex writer
preference, while the outer reader prevents the writer from proceeding.
Items now delegates locking and availability checks to itemsForCollection alone.
The helper still releases the service-map reader before taking the database
reader; collectEntriesForDB, visibility/recycle filtering, newItem and Path do
not reacquire that database lock. The visibility-config lookup briefly takes
the service-map reader while the database reader is held, as before; this change
does not introduce a service-map-to-database nested lock. collectionProps calls
the same helper without an outer database lock. No other direct duplicate
acquisition was found in this enumeration path. Registration's atomic boundary,
exact-instance selection, and writer serialization are unchanged.

The helper returns an allocated empty slice for an available empty collection,
and nil for unavailable collections, preserving Items' previous nil versus
empty distinction for locked/missing database/content. Missing root remains
empty. Missing map membership returns no items.

`internal/secretservice/items_test.go` adds six isolated specs. The concurrency
spec holds the service-map writer and observes the Items goroutine parked in
the helper's RWMutex read acquisition using runtime.Stack. It then runs the
real UpdateAndSaveWithUnlockedDatabases against a temporary KDBX and requires
the callback and save to complete before releasing the map lock; enumeration
then completes with the expected entry. This deterministically tests absence
of the outer reader, not a probabilistic scheduling loop or an instrumented
production helper. Five-second bounds and removal of the map entry on cleanup
allow even the original implementation to unwind. A temporary Go overlay
restoring the original Items reproduced the expected writer-entry timeout
(exit 1, no suite hang). That old implementation leaves the writer pending;
the corrected test deliberately requires it to acquire the lock instead of
forcing the exact fatal inner-read interleaving. Runtime stack symbol spelling
is a test/toolchain coupling, not a production hook. No live D-Bus is needed.

Verification used GOEXPERIMENT=runtimesecret and uncached `-count=1` throughout:
SecretService/dbpool suites passed, as did their complete `-race` suites
(`-timeout=120s` and `180s`). Focused FIDO (`-ginkgo.focus='Step 5'`,
`-ginkgo.skip='live uhid transport'`) passed **36 service / 28 HID**. Full FIDO
with the same live skip retained **81 service / 297 HID passing**, only the
**two expected AAGUID failures**, and three live skips. Separate non-FIDO tests
passed all ten tested packages (three without tests). Logs:
`/tmp/kpxcd-items-{suites,race,focused,fido,service,nonfido,old}.log`.
The initial test draft exposed a test-cleanup double-unlock on an overly strict
entry-list assertion; both were corrected before these passing runs. Changed Go
files were gofmt'd and `git diff --check` passed. No plan/tracker, Git writes,
live vault/device, policy/service, deployment, or Step 6 changes were made.

## Step 6: fixed identity, legacy configuration and authorization lifecycle

This supersedes only the Step 6 **later** labels above. Historical failures,
commands and counts are preserved. The starting accepted Step 5 measurement was
**81 service passed / 297 HID passed / two AAGUID failures / three live skips**.

### Identity and compatibility contract

`hid/authdata.go` contains one immutable production wire definition of product
AAGUID **ab449b5e-d0bf-4d8d-81b1-de5ec1a8c00e**. GetInfo and attested data both
use it. The unused copied-vendor service constant was removed. Independent
literal expectations remain in the original GetInfo and attested-data regression
probes; the remaining registration/live-test self-comparisons were also replaced
with literal product bytes. Discovery descriptor, device name, VID:PID, keys,
credential IDs, handles and assertion formats are unchanged. There is no migration,
random per-installation identity or release rotation. W2 §6 and C20 §5.4 remain
the source requirements; the UUID is approved product policy.

`Fido2Config` retains typed parsing of `aaguid`, `algorithms` and
`user_verification`, but no runtime consumer uses them. Every explicitly supplied
legacy key, even an empty value, emits an ignored/deprecated warning without its
value. Existing files load without being rewritten; malformed TOML types still
fail. Unknown `[fido2]` keys now fail explicitly, rather than silently becoming
defaults. Other sections' unknown-key behavior is unchanged. New defaults,
examples and active capability descriptions no longer promise those settings.
Browser generation remains ES256 only; explicit service/D-Bus creation retains
ES256/EdDSA and unchanged signatures. Correction to the historical Step 6 wording:
CLI create hardcodes ES256 only; those historical test results did not establish
CLI EdDSA generation. Verification is request-driven, with actual
approval verdicts, never a config downgrade or invented check. Config examples
correct COSE -25 to ECDH-ES + HKDF-256, not ES256K (-47); neither is implemented
for generation. The pre-existing unused service `COSEAlgES256K=-25` symbol is not
used by generation or advertisement and is outside this settings repair.

### Primary API and installed-library evidence

Read the primary
[polkit Authority D-Bus API](https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html),
particularly `CheckAuthorization`, `CancelCheckAuthorization`,
`CheckAuthorizationFlags`, `AuthorizationResult`, and `Subject`:

- Check takes `(sa{sv})`, action string, `a{ss}` details, uint32 flags and a
  cancellation string. `AllowUserInteraction` is 1; a nonempty ID is unique for
  the caller. Cancel takes that same string.
- Verified sender scoping against primary
  [polkitbackendauthority.c](https://raw.githubusercontent.com/polkit-org/polkit/master/src/polkitbackend/polkitbackendauthority.c)
  (retrieved 2026-11-16): `server_handle_check_authorization` and
  `server_handle_cancel_check_authorization` both construct the lookup key from
  `g_dbus_method_invocation_get_sender(invocation)` plus the ID. `check_auth_cb`
  removes the lookup before replying. Thus cancel from another connection cannot
  cancel this check; a completed check can legitimately race with “not found”.
- Nonempty details, including `polkit.message`, require a sufficiently authorized
  caller according to the API (for example root). The unprivileged daemon keeps
  details empty. Existing shipped fixed create/assert messages give generic
  attribution without interpolating untrusted RP/account text, HTML or commands.
- The pinned **godbus v5.2.2** source was inspected: `object.go` GoWithContext,
  `conn.go` send/SendWithContext, Close, outputHandler.sendAndIfClosed/close,
  and `transport_generic.go`. Call-context cancellation stops local reply
  tracking, not the remote polkit request. Dispatch writes synchronously even
  with GoWithContext; Close waits for the output lock before closing its socket.
  Merely adding a context or a Close goroutine would not bound a stalled write.

`authorization.go` therefore retains a standard-library Unix socket and passes
it to the existing godbus NewConn/Auth/Hello implementation. It does **not**
implement a custom D-Bus stack or add a dependency. Setup and each write have a
two-second I/O bound; closing the raw socket first avoids godbus's blocked-write
Close ordering. No Unix FD passing is required. The bounded connection explicitly
supports a single Linux `unix:path` or `unix:abstract` system-bus address (optional
GUID); other transports, ambiguous keys and address lists fail closed without
fallback. This is a documented deployment limitation, not live bus testing.

### Pending-request sequencing, approval and privacy

Each check has an atomic process-unique ID and its own connection. Context is
checked before connecting, before dispatch and after replies. Check dispatch
finishes before any Cancel dispatch; operation cancellation while dispatch is in
progress cannot let Cancel overtake Check. A canceled pending request sends Cancel
on that same live connection using an independent two-second cleanup context,
then closes it. A stalled Check write can add up to two seconds before cleanup.
Cleanup error/timeout or late success never approves. Gate Close closes admission
under its registration mutex, cancels pending checks and waits for bounded cleanup;
the daemon invokes it after canceling HID and before exiting. Buffered local completion
and godbus context cancellation release reply tracking without a goroutine waiting
for an eventual human answer. The existing HID context/generation handling for
CANCEL, deadline, INIT/resync, close and resident continuation is unchanged.

Under the unchanged shipped fresh `auth_self` policy, successful interactive
self-authentication establishes actual UP and UV together. An authorization bit
alone does not prove freshness: local `yes`, retained/cached authorization,
`auth_self_keep` or an agent bypass invalidates that policy assumption. No method,
PAM module or particular agent is required; no installed policy was changed or
live security verified. Cancellation does not roll back completed storage writes.
`doc/threat-model.md` records these assumptions and residual limits.

Full request/CBOR dumps had already been removed in Step 3. This repair removes
remaining RP/account identifying success logs and arbitrary storage-error text
from affected request failures, keeping fixed error/status diagnostics. The gate
no longer logs RP IDs, subject signatures or arbitrary remote error messages.

### Permanent tests and observed verification

- Config: legacy/nonempty/empty keys, exact warnings without values, new/default/
  example configs without retired values or warnings, no file rewrites, unknown
  key refusal and malformed typed values. Isolated real-KDBX tests prove legacy
  algorithm/verification settings do not change explicit local generation or
  actual assertion flags. Existing command tests still enforce required UV.
- Fake authorization boundary: exact method names, full typed Check arguments,
  empty safe details, correct action/flag, nonempty distinct IDs, matching Cancel
  ID, same open connection through acknowledgment, no pre-canceled dispatch,
  cancellation during connection/dispatch/prompt and just before success, denial,
  errors, malformed reply, deadline, cancel errors, bounded unacknowledged
  cleanup, no late approval and no cross-operation cancellation. Gate Close waits
  for cancellation acknowledgment/connection closure, refuses later admission,
  and races safely against concurrent Approve registration. Request contexts
  finish; concurrent operations use separate connections. No host polkit runs.
- Real godbus with net.Pipe proves blocked dispatch terminates and Close completes;
  temporary Unix fake sockets prove stalled Auth is interrupted by cancellation
  and deadline and setup goroutines return. Socket parsing has positive/negative
  fixtures. These fakes do not establish actual host-agent behavior.
- HID request privacy tests inject identifying request data and storage errors;
  only fixed creation/assertion failure diagnostics are logged. Existing HID
  operation-generation, approval and resident lifecycle race tests remain green.

All commands used `GOEXPERIMENT=runtimesecret` and uncached `-count=1`:

```sh
GOEXPERIMENT=runtimesecret go test ./internal/config ./internal/daemon -count=1 -timeout=60s
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.focus='Step 6|product AAGUID|GetInfo' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test ./internal/fido2/... -v -count=1 -timeout=60s -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test -race ./internal/fido2/... -v -count=1 -timeout=180s -ginkgo.focus='Step 6|Step 5|Step 4|approval|CTAPHID_CANCEL|keeps receive ownership|keeps approval ownership|discards partial reception' -ginkgo.skip='live uhid transport'
GOEXPERIMENT=runtimesecret go test -race ./internal/config ./internal/daemon -count=1 -timeout=120s
GOEXPERIMENT=runtimesecret go list ./... | grep -v '/internal/fido2' > /tmp/kpxcd-step6-nonfido-packages
GOEXPERIMENT=runtimesecret go test $(< /tmp/kpxcd-step6-nonfido-packages) -count=1 -timeout=60s
git diff --check
```

Focused FIDO: **35 service / 5 HID passed**, no failures (81/298 focus-skipped).
Full FIDO: **116 service / 300 HID passed**, zero failures, **three live skipped**.
Both original AAGUID failures are green without weakened expectations. Focused
race: **71 service / 123 HID passed**, no race reports (45/180 focus-skipped).
Separate Step 6-only race reruns with `-ginkgo.seed=11` and `12` also passed
(**35 service / 1 HID** each); logs `/tmp/kpxcd-step6-race-{11,12}.log`.
Config/daemon normal and separate race runs passed. Non-FIDO regressions passed
all ten tested packages, three without tests, without Ginkgo flags. Logs:
`/tmp/kpxcd-step6-{config-daemon,focused,fido,race,config-daemon-race,nonfido}.log`.
Changed Go files were gofmt'd and diff whitespace checks passed.

Only Step 6 is implemented here. The two identity/capability table corrections in
passkeys/feature-matrix retire false promises, not a refreshed Step 7 browser
matrix. Broad documentation/build/browser verification remains Step 7. No nested
delegation, plan/tracker edits, Git writes/staging/commit/push/tag/worktree,
dependency changes, deployment/restarts, live vault/device/auth requests, host
policy changes or migrations occurred. These isolated tests are not live security
verification, universal browser compatibility or FIDO certification.

## Step 7 final offline summary (2026-11-16)

Documentation/verification only: no source changes, tracker completion, deployment,
restart, live vault/device/account/polkit access, host-policy or Git writes.
The mandatory audit rows above are covered by this consolidated map; it supersedes
historical **later/red/unresolved** statuses, not their recorded observations.

| In-scope requirements | Implementation | Permanent offline evidence (under internal/) |
|---|---|---|
| Exact handle, full RP/type/ID allow/exclude selection, imported preservation, overflow/save refusal | fido2/ctap.go, service.go; hid/commands.go | fido2/identity_test.go, service_test.go; hid/identity_test.go, conformance_test.go |
| Independent UP/UV, actual flags, required consent/error order, complete validation, PIN refusal, response shapes/no-argument commands | hid/commands.go, gate.go, authdata.go; fido2/service.go | hid/validation_test.go, approval_test.go; fido2/validation_test.go |
| Canonical CBOR, duplicate/tag/indefinite/depth/type rejection | hid/request.go | hid/validation_test.go literal wire fixtures; strict decoder recommendations separately labeled above |
| Honest ES256 browser generation, retained local/import signing, normal probe RP semantics | hid/authenticator.go, commands.go; fido2/ctap.go, service.go | hid/validation_test.go, conformance_test.go; fido2/validation_test.go, identity_test.go |
| Framing boundaries/limits/padding, CID ownership/busy, receive timeout/errors, INIT/CANCEL/stale output | hid/descriptor.go, authenticator.go, commands.go | hid/transport_test.go, conformance_test.go, uhid_output_test.go; synthetic adapter, not kernel evidence |
| Safe selected-instance resident replacement, unlocked-only ownership, unrelated-field/no-migration preservation | fido2/resident.go, service.go, ctap.go; dbpool/pool.go, save.go | fido2/resident_test.go; dbpool/atomic_test.go; connected secretservice/items_test.go |
| Multiple accounts/count/GetNextAssertion, privacy, expiry, lock/reopen/resync invalidation | hid/resident.go, commands.go, authenticator.go; fido2/resident.go | hid/resident_test.go; fido2/resident_test.go (including real signature verification) |
| Fixed identity and ignored legacy settings/warnings | hid/authdata.go, authenticator.go; config/config.go | hid/conformance_test.go, hid_test.go; config/config_test.go; fido2/validation_test.go |
| Authorization cleanup and no request/account dumps | fido2/presence.go, authorization.go; hid/commands.go | fido2/presence_test.go, authorization_test.go; hid/privacy_test.go; fake services only |

Source/caller inspection also corrected stale documentation: active D-Bus
CreatePasskey/AssertPasskey are not stubs. CLI implements list/create/remove/import,
not assert. CLI create explicitly requests ES256; service/D-Bus callers can request
EdDSA. Local random-handle creation is not browser registration and remains
append-only. D-Bus AssertPasskey reports UP only through a separate existing polkit
path; native ceremony cancellation/UV claims do not extend to that path.

### Commands and observed results

Makefile and scripts were read before execution. `make check` was deliberately
not run: it formats the repository and does not explicitly skip live UHID tests.
`make install`, `pamtester`, login, device tests, and `scripts/test-libsecret.sh`
were not run. The latter starts a daemon and creates a database. mktestdb was
compiled only, never executed. All commands inherited
`GOEXPERIMENT=runtimesecret`. Outputs/exits are in
`/tmp/kpxcd-step7-offline/`; these are local temporary evidence, not release artifacts.

```sh
export GOEXPERIMENT=runtimesecret
go list ./... > /tmp/kpxcd-step7-offline/packages
grep -v '/internal/fido2' /tmp/kpxcd-step7-offline/packages > /tmp/kpxcd-step7-offline/nonfido-packages
go test ./internal/fido2/... -v -count=1 -timeout=180s -ginkgo.skip='live uhid transport'
go test $(< /tmp/kpxcd-step7-offline/nonfido-packages) -count=1 -timeout=180s
go test -race ./internal/fido2/... -v -count=1 -timeout=300s -ginkgo.skip='live uhid transport'
go test -race $(< /tmp/kpxcd-step7-offline/nonfido-packages) -count=1 -timeout=300s
go vet ./...
go build -trimpath -o /tmp/kpxcd-step7-offline/kpxcd ./cmd/kpxcd
go build -trimpath -o /tmp/kpxcd-step7-offline/kpxcctl ./cmd/kpxcctl
go build -trimpath -o /tmp/kpxcd-step7-offline/mktestdb ./scripts/mktestdb
CARGO_TARGET_DIR=/tmp/kpxcd-step7-offline/pam-target make test-pam
CARGO_TARGET_DIR=/tmp/kpxcd-step7-offline/pam-target cargo build --release --manifest-path contrib/pam/kpxcd-pam/Cargo.toml
```

| Check | Result | Log basename |
|---|---|---|
| Full uncached FIDO | Exit 0; 116 service + 300 HID passed, 3 live skipped | fido.log |
| Full uncached non-FIDO | Exit 0; ten tested packages passed, three no-test packages (including mktestdb) | nonfido.log |
| Full FIDO race, no focus filter | Exit 0; 116 service + 300 HID passed, 3 live skipped, no race report | fido-race.log |
| Full non-FIDO race | Exit 0; all ten tested packages passed; three no-test packages | nonfido-race.log |
| Vet all packages | Exit 0, no diagnostics | vet.log |
| Three Go binaries, /tmp outputs only | Exit 0, no diagnostics; binaries not executed | build.log |
| PAM format check + cargo test | Exit 0; **zero Rust tests**, compile/format evidence only, not PAM runtime evidence | pam.log |
| PAM release build, /tmp target | Exit 0 | pam-build.log |
| gofmt check on changed/untracked Go only | 37 files clean; no gofmt writes | format.log |
| Tracked diff whitespace | Exit 0 | diff-check.log |

Additional tracked/untracked text whitespace inspection found no trailing whitespace
but three pre-existing Step 6 files lack final newlines:
`contrib/kpxcd.toml.example`, `doc/config.md`, `doc/threat-model.md`.
The combined custom whitespace check therefore exits 1 (format.exit), despite clean
Go formatting. They were preserved rather than silently changing prior-step files.
This is a formatting limitation, not a functional test blocker. Final documentation
whitespace was rechecked after this summary was added.

### Browser verification matrix (awaiting approval)

Every cell below is **NOT RUN / awaiting approval** for the current candidate.
No deployed browser/kernel/polkit version is recorded because no candidate was
deployed. For each future run record exact candidate revision/build, OS/kernel,
browser version, agent/policy, site/options, expected versus observed result and
sanitized evidence. Use an isolated vault/test identity and controlled WebAuthn
site first; GitHub/Amazon require additional explicit deployment/account-change
approval and a verified recovery method. A site UI not exposing an option is not
a pass: use a controlled harness or record the case unavailable.

| Scenario / observations required | Chrome, controlled site | Firefox, controlled site | Chrome, GitHub/Amazon later | Firefox, GitHub/Amazon later |
|---|---|---|---|---|
| Registration then authentication; exact user handle, ES256, fixed AAGUID, counters | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Username-first allowCredentials; later allow-list candidate and wrong-RP refusal | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Discoverable/username-less sign-in and returned account identity | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Multiaccount selection; continuation, same-account selected-destination replacement and ambiguity refusal | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Silent up=false/uv=false allow-list probes, no prompt; exclusions require consent before disclosure | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Required and preferred UV, actual flags and no downgrade on denial | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Cancel, deny, timeout, INIT/resync where harness supports it; no stale prompt/reply; lock during ceremony/continuation | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |
| Existing imported credentials, preserved IDs/handles and USB-excluding original transport hints | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval | NOT RUN / awaiting approval |

Separate live UHID transport specs and fresh-auth/agent cancellation/security checks
are also **NOT RUN / awaiting approval**. Synthetic UHID envelopes do not prove
kernel transport works; fake polkit tests do not prove policy freshness or real
agent dismissal. Historical browser successes do not fill any current matrix cell.

### Residual limits and independent-review handoff

No offline functional blocker was observed by these checks; this is not final
code/adversarial review. All mandatory in-scope audit rows have the implementation
and test mapping above, while live validation remains outstanding. Decoder SHOULD
rejection policy is implemented but is not recast as a normative MUST. Optional
ClientPIN/extensions and destructive Reset remain explicitly unsupported; the
missing Reset prevents claiming complete advertised-version conformance or FIDO
certification merely from this repair. No certification suite was run.

Review the complete Steps 1–6 source/test diff, especially lock ordering/rollback,
exact open-instance replacement and signing, pending-state invalidation, CBOR
error order, transaction generation/output boundaries, and bounded polkit dispatch
versus Cancel sequencing. Verify no-data-migration and imported preservation
against actual callers, not only fixtures. Fresh authentication depends on local
policy; one Unix bus address is a deployment limitation. Entered writes cannot be
recalled, post-rename failure can leave changed disk, backup restore can roll
counters back, and hidden locked-vault matches are deliberately outside replacement
visibility. Historical incorrect user handles are generally unrecoverable; only
affected credentials may require user-approved re-registration. Local import cannot
repair USB-excluding server hints. Amazon's rejection reason is still unconfirmed;
no universal compatibility or solved-Amazon claim is made. Independent final
review and approval-controlled live tasks remain open; no tracker tasks were marked.

## Final-review corrections (2026-11-16)

The final storage review found that HID's full-set enumeration followed by a
separate selected-reference assertion did not make full-set invalidation atomic.
An already returned or later account could change between those operations while
the unchanged next account still signed. The earlier offline results above remain
historical observations, not proof that this gap was safe.

`CredentialStore.AssertResident` now accepts the selected reference **and the
entire original reference slice**. Both initial resident assertions and
GetNextAssertion pass that slice. HID no longer enumerates a second snapshot as
an authority. The service resolves only the selected database pointer before
entering the existing `UpdateAndSaveWithUnlockedDatabases` boundary; that pointer
lookup does not authorize signing. Inside the boundary it checks every original
reference against unlocked membership, database UUID/open-instance ID, eligible
(non-recycled) entry UUID, RP, credential ID and user handle before selected-key
signing or any counter mutation. All references must belong to the same RP and
the selected reference must be in the original set.

No dbpool transaction framework or lock policy was added. The reused boundary
holds the pool read lock, then database locks ordered by InstanceID (target write,
others read), through validation, selected signing, counter update and target
save. Lock/reopen/membership changes and independent database writers cannot
enter the validation/save gap. Locked databases remain excluded, never unlocked
by this path. Existing exhaustion, identity, eligible-entry, save conflict and
rollback safeguards remain; a failed save exposes no signature. HID clears
pending state and returns NOT_ALLOWED when the full set is invalid. Existing
context, cancellation, resync and operation-generation response checks remain.
This does not promise to undo a storage write that completed before cancellation.

### Regression and independent boundary evidence

- Ten new real-KDBX service cases capture three original accounts in three
  databases, successfully return the first, then lock, lock/reopen, remove,
  replace, or independently edit either the already-returned or later account.
  The selected next reference is unchanged. Each refuses without a signature,
  leaves its counter zero and its on-disk bytes unchanged. Removal/replacement
  use a separate service instance, and direct UpdateAndSave bypasses FIDO's
  per-service mutex entirely. Another real-KDBX case refuses the initial
  assertion if a different enumerated candidate changed before its boundary.
- Two channel-synchronized HID regressions block after the original snapshot
  reaches AssertResident but before its authoritative validation, invalidate
  the already-returned or later candidate, and verify NOT_ALLOWED, no additional
  signing and cleared pending state. Blocking fake stores have a bounded release
  wait; existing resync/cancellation blocked-store tests still pass.
- The unchanged real-storage `dbpool/atomic_test.go` boundary specs exercise
  target and other-database UpdateAndSave writers plus pool lock/open changes.
  Callback barriers and nonblocking TryLock/TryRLock assertions prove exclusion
  while validation/save owns the locks, not merely elapsed sleep time. Full
  dbpool race tests (21 specs) and connected SecretService race tests (62 specs)
  pass; the latter retains coverage against the recursive-reader deadlock.
- A temporary Go overlay removes only full-original-set validation, retaining
  selected-target checks and all the new tests. All ten nonselected-change
  service cases fail (they unexpectedly sign), independently demonstrating that
  selected checks alone are insufficient. Expected failing evidence is in
  `/tmp/kpxcd-final-correction/selected-only-repro.log` (exit 1), with the overlay
  and selected-only source alongside it. No repository source was reverted for
  this negative-control run. Normal full-suite runs use no overlay.
- Existing real ES256 signature verification, imported preservation, counter
  exhaustion, save failure and rollback tests remain green.

### Documentation corrections

Config documentation, the example and historical Step 6 wording now distinguish
service/D-Bus ES256+EdDSA generation from CLI create's hardcoded ES256 request.
The historical Step 6 test results are preserved with a correction note. README's
opening passkey claim now describes native Linux UHID CTAP2 without promising
support in every browser; current-candidate compatibility remains unverified.

Source inspection of daemon/socket setup, xdg helpers and dbpool opening confirms
there is no control.sock JSON-RPC server, daemon-start umask setting, or startup
warning for world-readable vault/keyfiles. The threat model removes those false
interfaces/protection claims, lists the actual optional PAM socket/native UHID
surface, distinguishes directly chmod'd sockets from systemd activation/session
bus ownership, and keeps existing-file permission checks as future hardening.
No protection was implemented or policy changed by this documentation correction.

### Final safe recheck

All Go checks explicitly used `GOEXPERIMENT=runtimesecret`, uncached tests and
separate `/tmp/kpxcd-final-correction/` logs/exits. No live tests ran.

```sh
export GOEXPERIMENT=runtimesecret
go list ./... > /tmp/kpxcd-final-correction/packages
grep -v '/internal/fido2' /tmp/kpxcd-final-correction/packages > /tmp/kpxcd-final-correction/nonfido-packages
go test ./internal/fido2/... -v -count=1 -timeout=180s -ginkgo.skip='live uhid transport'
go test $(< /tmp/kpxcd-final-correction/nonfido-packages) -count=1 -timeout=180s
go test -race ./internal/fido2/... -v -count=1 -timeout=300s -ginkgo.skip='live uhid transport'
go test -race $(< /tmp/kpxcd-final-correction/nonfido-packages) -count=1 -timeout=300s
go test -race ./internal/dbpool ./internal/secretservice -v -count=1 -timeout=180s
go vet ./...
go build -trimpath -o /tmp/kpxcd-final-correction/kpxcd ./cmd/kpxcd
go build -trimpath -o /tmp/kpxcd-final-correction/kpxcctl ./cmd/kpxcctl
go build -trimpath -o /tmp/kpxcd-final-correction/mktestdb ./scripts/mktestdb
```

| Recheck | Observed result | Log basename |
|---|---|---|
| Full FIDO | Exit 0; **127 service + 302 HID passed**, 3 live skipped | fido.log |
| Full FIDO race | Exit 0; **127 service + 302 HID passed**, 3 live skipped; no race report | fido-race.log |
| Full non-FIDO, no Ginkgo flags | Exit 0; ten tested packages pass, three have no tests | nonfido.log |
| Full non-FIDO race, no Ginkgo flags | Exit 0; includes dbpool/SecretService/config/daemon; no race report | nonfido-race.log |
| Separate complete dbpool/SecretService race | Exit 0; **21 + 62 specs passed** | storage-race.log |
| Vet all packages | Exit 0, no diagnostics | vet.log |
| Three Go builds, /tmp outputs, never executed | Exit 0 | build.log |
| Changed/new Go formatting and text whitespace, including untracked files | Exit 0; 37 Go files and 48 changed/new files checked | format.log |
| Tracked diff whitespace | Exit 0 | diff-check.log |

The three final newlines repaired before this correction remain present in
`contrib/kpxcd.toml.example`, `doc/config.md` and `doc/threat-model.md`. The new
successful formatting recheck supersedes the earlier formatting limitation; the
historical Step 7 `format.exit` failure above is deliberately retained. PAM code
was unaffected and its prior compile/format-only evidence is unchanged; no PAM
runtime check was performed. Final independent review and all approval-controlled
live tasks still remain open. No plan/tracker edits, nested delegation, Git
writes, deployment/restart, live vault/UHID/polkit/account access, host-policy
changes, dependencies or migrations occurred.

### Lead acceptance after final re-review

The lead accepts the storage, protocol/authentication, and documentation reviews.
No offline blockers remain after the full-set assertion correction. The storage
reviewer independently reran the negative control: all ten intended cases failed.
Full FIDO, dbpool and Secret Service race checks passed during re-review.
The lead also reran the full nonlive FIDO suite and `go vet ./...`; both passed.

The tracker records 32 of 35 tasks complete. Three tasks remain approval-blocked:
live kernel transport, deployment/account-change approval, and the browser matrix.
Live polkit freshness and agent dismissal also remain unverified. Offline
acceptance does not authorize deployment, live credential changes, or Git writes.


