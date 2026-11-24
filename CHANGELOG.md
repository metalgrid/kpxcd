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

- Added per-app notification suppression for Secret Service access: the first
  secret read by an app notifies, repeat reads within `notify_cache_ttl`
  seconds are silent, and each read refreshes the window.
- Added PAM auto-unlock via Unix socket IPC with HKDF-derived tokens.
- Added Secret Service, SSH agent, FIDO2/passkey, and D-Bus daemon surfaces.
- Added systemd units, shell completions, and man pages.
- Added repository hygiene files and CI checks for Go and the Rust PAM module.
