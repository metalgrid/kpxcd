# Changelog

All notable changes to kpxcd will be documented in this file.

The project currently has no stable release. Breaking changes may occur before
`v1.0.0`.

## Unreleased

Security and correctness fixes from an independent two-reviewer audit:

- Fixed a data race on database lock state (daemon PAM socket, D-Bus API,
  SSH agent callbacks) and on the daemon config pointer at SIGHUP.
- Pool lock/unlock events are now always delivered (remove-on-lock and
  Secret Service cleanup no longer depend on a non-blocking channel send).
- Secret Service session map is guarded by a single mutex; Session.Close is
  exported and removes the session; DH public keys are range-checked.
- Secret Service emits the spec CollectionCreated/CollectionDeleted signals,
  unexports and rebinds aliases on collection removal, and derives
  collection paths with a UUID suffix so same-basename databases cannot collide.
- Secret Service SearchItems matches `title` and `URL` exactly.
- Prompt objects follow the spec shape (window-id argument, object-path
  result, single completion); CreateCollection is refused instead of
  returning a prompt that never completes.
- The daemon starts the SSH agent before exporting D-Bus, so the Ssh* API
  holds a live agent instead of nil.
- SshTestSign and `kpxcctl ssh test-sign` are removed (prompt-less signing
  oracle).
- SSH keys load only for entries with KeeAgent allowUseOfSshKey opt-in
  (addAtDatabaseOpen for auto-load); the recycle bin is excluded.
- External database edits now reload the in-memory copy (previously the
  watcher only logged, and later writes were refused as "changed on disk").
- Database fingerprints at open are taken from the open file descriptor;
  failed saves restore the full content including the binary table.
- New passkeys use KeePassXC's attribute names; legacy kpxcd entries are
  still read. The polkit policy declares only actions the daemon enforces.
- The PAM socket read is bounded by a deadline.

SSH rework (self-sufficient; KeePassXC is never required):

- Fixed the KeeAgent parser to read real KeePassXC EntrySettings XML
  (previously only our own nonstandard form parsed, so KeePassXC-annotated
  vaults loaded no keys); legacy form is read-only.
- SSH keys are discovered via KeeAgent settings when present (deny always
  wins), otherwise via the kpxcd KPXCD_SSH_KEY marker; bare attachments no
  longer auto-load. Manage them with `kpxcctl ssh autoload` (menu or
  explicit on/off) — applies at next unlock.
- `kpxcctl ssh import` without arguments scans ~/.ssh and offers a menu,
  skipping keys already stored; `ssh generate`/`ssh import` write both the
  kpxcd marker and valid KeeAgent.settings, and refuse to overwrite an
  existing different key.
- `kpxcctl ssh export` is now available, gated by polkit auth_self
  (org.keepassxc.daemon.ssh.export), writing 0600 O_EXCL files, encrypted
  with a passphrase by default.

- Added per-app notification suppression for Secret Service access: the first
  secret read by an app notifies, repeat reads within `notify_cache_ttl`
  seconds are silent, and each read refreshes the window.
- Added PAM auto-unlock via Unix socket IPC with HKDF-derived tokens.
- Added Secret Service, SSH agent, FIDO2/passkey, and D-Bus daemon surfaces.
- Added systemd units, shell completions, and man pages.
- Added repository hygiene files and CI checks for Go and the Rust PAM module.
