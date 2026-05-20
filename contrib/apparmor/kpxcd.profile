# AppArmor profile for kpxcd — KeePassXC headless daemon
#
# This profile confines kpxcd according to its threat model (doc/threat-model.md).
# It restricts kpxcd to only the files, sockets, and IPC mechanisms it needs,
# while denying network access, ptrace, and unnecessary filesystem access.
#
# Install:
#   sudo cp contrib/apparmor/kpxcd.profile /etc/apparmor.d/usr.bin.kpxcd
#   sudo apparmor_parser -r /etc/apparmor.d/usr.bin.kpxcd
#
# Threat model justification:
#   kpxcd holds decrypted KeePass database contents in mlock'd memory and serves
#   them over D-Bus and a Unix socket. The threat model (doc/threat-model.md)
#   identifies several attack vectors that this profile mitigates:
#
#   1. Memory inspection by other processes:
#      - Deny ptrace, preventing other processes from reading /proc/$pid/mem.
#      - Use mlock for secure memory (handled by the binary, not AppArmor).
#
#   2. Network exposure:
#      - kpxcd does not need network access. All interfaces (D-Bus, SSH agent,
#        control socket) use local Unix domain sockets.
#      - Deny all network protocols (inet, inet6, netlink, etc.).
#
#   3. Filesystem access:
#      - Only read .kdbx database files and keyfiles from the user's home.
#      - Only read configuration from ~/.config/kpxcd/.
#      - Only write sockets and runtime files to $XDG_RUNTIME_DIR/kpxcd/.
#      - Deny write access elsewhere to prevent tampering or data exfiltration.
#
#   4. D-Bus access:
#      - Allow session bus communication for:
#        * org.keepassxc.Daemon (own name, serve methods)
#        * org.freedesktop.secrets (own name, Secret Service interface)
#        * org.freedesktop.PolicyKit1 (check authorizations)
#      - Deny system bus access (not needed).
#
#   5. Process tracing:
#      - Deny ptrace to prevent memory inspection by same-UID processes.
#      - This complements kernel.yama.ptrace_scope >= 1.

#include <tunables/global>

profile kpxcd @{HOME}/bin/kpxcd flags=(attach_disconnected,mediate_deleted) {
  # ===========================================================================
  # Include base rules
  # ===========================================================================

  #include <abstractions/base>
  #include <abstractions/nameservice>

  # ===========================================================================
  # Capability grants
  # ===========================================================================

  # mlock(2) — required for locking decrypted database pages in memory.
  # See threat model § Mitigations by Layer → Memory.
  capability ipc_lock,

  # Allow setting resource limits (e.g., RLIMIT_MEMLOCK for mlock).
  capability sys_resource,

  # ===========================================================================
  # Executable
  # ===========================================================================

  # The kpxcd binary itself.
  @{HOME}/bin/kpxcd                    mr,
  /usr/bin/kpxcd                       mr,
  /usr/local/bin/kpxcd                 mr,

  # Shared libraries needed for execution.
  /lib/**                              rm,
  /usr/lib/**                          rm,

  # ===========================================================================
  # Configuration files
  # ===========================================================================

  # Read/write configuration from ~/.config/kpxcd/config.toml.
  # kpxcd creates the embedded default config on first run.
  owner @{HOME}/.config/kpxcd/          rw,
  owner @{HOME}/.config/kpxcd/**        rw,

  # Read KeePassXC config for database MRU and display names.
  owner @{HOME}/.config/keepassxc/      r,
  owner @{HOME}/.config/keepassxc/**    r,

  # ===========================================================================
  # Database files
  # ===========================================================================

  # Read .kdbx database files from the user's home directory and common
  # locations. These are encrypted at rest; kpxcd decrypts them in memory.
  owner @{HOME}/**.kdbx                rw,
  owner @{HOME}/Documents/**.kdbx      rw,
  owner @{HOME}/.local/share/**.kdbx   rw,

  # Read keyfiles (any file referenced in config).
  owner @{HOME}/**                     r,

  # Allow reading from external media if mounted under /media or /mnt
  # (for USB drives containing .kdbx files or keyfiles).
  /media/**/**.kdbx                    r,
  /mnt/**/**.kdbx                      r,
  /media/**                            r,
  /mnt/**                              r,

  # ===========================================================================
  # Runtime directory (sockets, PID files)
  # ===========================================================================

  # Read and write to the kpxcd runtime directory under XDG_RUNTIME_DIR.
  # This is where the SSH agent socket and control socket are created.
  owner /run/user/*/kpxcd/             rw,
  owner /run/user/*/kpxcd/**           rw,

  # Create Unix domain sockets in the runtime directory.
  owner /run/user/*/kpxcd/ssh.sock     rw,
  owner /run/user/*/kpxcd/control.sock rw,

  # Also handle the XDG_RUNTIME_DIR variable path pattern.
  owner @{RUNTIME_DIR}/kpxcd/          rw,
  owner @{RUNTIME_DIR}/kpxcd/**        rw,

  # ===========================================================================
  # Credential directory (systemd LoadCredential)
  # ===========================================================================

  # Read systemd credentials and read/write kpxcd's age-sealed PAM credentials.
  owner /run/host/**                   r,
  owner @{HOME}/.local/share/kpxcd/    rw,
  owner @{HOME}/.local/share/kpxcd/**  rw,

  # ===========================================================================
  # D-Bus
  # ===========================================================================

  # Own the kpxcd service name on the session bus.
  dbus (send, receive)
      bus=session
      peer=(name=org.freedesktop.DBus, label=unconfined),

  dbus (send, receive)
      bus=session
      interface=org.freedesktop.DBus
      peer=(name=org.freedesktop.DBus, label=unconfined),

  # org.keepassxc.Daemon — custom management API.
  dbus (send, receive)
      bus=session
      name=org.keepassxc.Daemon
      interface=org.keepassxc.Daemon
      path=/org/keepassxc/Daemon
      peer=(label=unconfined),

  # org.freedesktop.secrets — Secret Service compatibility.
  dbus (send, receive)
      bus=session
      name=org.freedesktop.secrets
      interface=org.freedesktop.Secret.*
      path=/org/freedesktop/secrets{,/**}
      peer=(label=unconfined),

  # org.freedesktop.PolicyKit1 — authorization checks.
  dbus (send, receive)
      bus=session
      name=org.freedesktop.PolicyKit1
      interface=org.freedesktop.PolicyKit1.Authority
      path=/org/freedesktop/PolicyKit1/Authority
      peer=(label=unconfined),

  # Read screen lock signals (to lock databases on screen lock).
  dbus (receive)
      bus=session
      interface=org.freedesktop.ScreenSaver
      path=/org/freedesktop/ScreenSaver
      member=ActiveChanged
      peer=(label=unconfined),

  dbus (send)
      bus=session
      interface=org.freedesktop.ScreenSaver
      path=/org/freedesktop/ScreenSaver
      member=GetActive
      peer=(label=unconfined),

  # Allow kpxcctl to connect as a D-Bus client.
  dbus (receive)
      bus=session
      peer=(label=kpxcctl),

  # ===========================================================================
  # Notifications (desktop notifications for secret access)
  # ===========================================================================

  dbus (send)
      bus=session
      interface=org.freedesktop.Notifications
      path=/org/freedesktop/Notifications
      member=Notify
      peer=(label=unconfined),

  # ===========================================================================
  # Logging
  # ===========================================================================

  # Allow writing to stderr (when not using journald).
  owner @{PROC}/@{pid}/fd/[0-9]*     w,

  # Allow writing to the system journal (when log_to_journald = true).
  /run/systemd/journal/socket         w,
  /run/systemd/journal/stdout         rw,
  /dev/log                            w,

  # ===========================================================================
  # PC/SC (optional, for YubiKey challenge-response)
  # ===========================================================================

  # PC/SC daemon socket for smart card access (YubiKey).
  /run/pcscd/pcscd.comm               rw,
  /var/run/pcscd/pcscd.comm           rw,

  # ===========================================================================
  # DENY rules — hardening
  # ===========================================================================

  # Deny all network access. kpxcd only communicates via local Unix sockets
  # and D-Bus (which uses local sockets). See threat model § 5 (Network Attacker).
  deny network inet stream,
  deny network inet dgram,
  deny network inet6 stream,
  deny network inet6 dgram,
  deny network netlink raw,
  deny network netlink dgram,
  deny network packet stream,
  deny network packet dgram,
  deny network axon stream,

  # Deny ptrace to prevent memory inspection by other processes.
  # See threat model § 1 (Unprivileged Local Process) — memory scanning.
  deny ptrace,

  # Deny loading kernel modules.
  deny capability sys_module,

  # Deny raw I/O port access.
  deny capability sys_rawio,

  # Deny mounting filesystems.
  deny capability sys_admin,

  # Deny access to other users' home directories.
  deny owner /home/*/**  rwx,

  # ===========================================================================
  # Allow signal reception (for graceful shutdown)
  # ===========================================================================

  signal (receive) set=(term, hup, int, quit),

  # ===========================================================================
  # Include local overrides
  # ===========================================================================

  # Site-specific additions can be placed in:
  #   /etc/apparmor.d/local/usr.bin.kpxcd
  #include <local/usr.bin.kpxcd>
}
