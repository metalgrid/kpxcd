# Contributing

Thanks for helping improve kpxcd.

## Development Setup

Requirements:

- Go 1.26+ with `GOEXPERIMENT=runtimesecret`;
- Rust stable for the optional PAM module;
- Linux with systemd for full integration testing.

## Checks Before Submitting

```bash
# Go formatting, vet, and tests
make check

# PAM module checks
make test-pam
```

If `golangci-lint` is installed, run:

```bash
make lint
```

## Style

- Keep daemon code Linux-focused and headless.
- Do not log secrets, database passwords, PAM tokens, private keys, or raw
  Secret Service payloads.
- Prefer small, focused changes with tests beside the affected package.
- Update `doc/` and man pages when behavior or command-line usage changes.

## Security Changes

For changes touching PAM, Secret Service, SSH agent, FIDO2, or memory handling,
include a short threat-model note in the PR description and update
`doc/security-audit.md` when appropriate.
