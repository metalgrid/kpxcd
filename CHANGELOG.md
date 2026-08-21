# Changelog

All notable changes to kpxcd will be documented in this file.

The project currently has no stable release. Breaking changes may occur before
`v1.0.0`.

## Unreleased

- Added per-app notification suppression for Secret Service access: the first
  secret read by an app notifies, repeat reads within `notify_cache_ttl`
  seconds are silent, and each read refreshes the window.
- Added PAM auto-unlock via Unix socket IPC with HKDF-derived tokens.
- Added Secret Service, SSH agent, FIDO2/passkey, and D-Bus daemon surfaces.
- Added systemd units, shell completions, and man pages.
- Added repository hygiene files and CI checks for Go and the Rust PAM module.
