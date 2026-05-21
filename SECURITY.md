# Security Policy

kpxcd handles KeePass database secrets, SSH keys, and PAM-derived unlock tokens.
Please report security issues privately.

## Reporting a Vulnerability

Email the maintainers or open a private GitHub security advisory for this
repository. Include:

- affected version or commit;
- operating system and systemd/PAM setup, if relevant;
- steps to reproduce or a proof of concept;
- impact assessment and any suggested mitigation.

Please do not file public issues for suspected vulnerabilities until a fix or
mitigation is available.

## Supported Versions

Until the first stable release, security fixes target the `main` branch only.
Tagged releases may be issued for high-impact fixes.

## Scope

Security-sensitive areas include:

- PAM auto-unlock and socket handoff;
- in-memory secret handling and wiping;
- Secret Service access control;
- SSH agent signing and key lifetime handling;
- FIDO2/passkey private-key storage and assertion.
