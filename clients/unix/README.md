# Hermes Connector Unix development client

**Development only.** Linux and macOS command-line implementation of the
Hermes per-user broker client. This is **not** a replacement for the Windows
GUI or a completed, signed multi-OS release. Source and binaries are built in
GitHub Actions (`unix-build.yml`) for Linux x64/arm64 and macOS x64/arm64;
usage requires a separate operator-approved enrollment. The development
packages are unsigned and not yet a public release.

## Architecture

- The single program chooses GR1 or GR2 for **new** registration. Existing
  tickets are pinned to their original HTTPS broker and may not be silently
  transferred. Gate host keys are checked and pinned from the approved
  enrollment response (`known_hosts`, `StrictHostKeyChecking=yes`).
- OpenSSH **Client** establishes the outbound `ssh -R` tunnel. The receiver
  is a local authenticated Unix-agent bound only to `127.0.0.1`, executing
  `/bin/sh` under the **same Unix UID** as the Connector; no sudo or additional
  account is used for remote commands. This uses the same HMAC-SHA256 wire
  format as the Windows client/operator script.
- One process per user, TTL checks, reconnect with bounded SSH timeouts and
  keepalive. Resident mode uses an explicitly granted unlimited broker lease.
  Merely requesting an unlimited lease never authorizes it.
- The broker ticket is stored **only** in native SecretService (Linux)
  or macOS Keychain through `keyring`, with no plaintext fallback. On a
  headless system without an unlocked keyring, the client refuses to start.
- Linux `systemd --user` and macOS per-user `LaunchAgents` autostart are
  opt-in and do not alter system-level services. Installation is for the NEXT
  login; after logout/pre-login availability is not proven.
- Development GUI (`gui`, `gui --resident`) uses the same CLI executable as a
  child. A collapsible on-disk-redacted journal, support/resident choice,
  install/status controls and `pystray` status-bar icon are included.
  The system tray may be unavailable on some Wayland/X11 desktop environments;
  in that case the GUI does not silently hide or become uncloseable.
  Real display/tray interaction and signing/notarization remain acceptance
  blockers; headless CI tests cover helpers and packaging only.

## Commands

```sh
HermesConnector gui                    # окна поддержки, трей, журнал
HermesConnector gui --resident         # постоянный режим в трее
HermesConnector doctor
HermesConnector setup-ssh client
HermesConnector setup-ssh client --install
HermesConnector setup-ssh server
HermesConnector setup-ssh server --install  # requires interactive approval; may open TCP/22
HermesConnector connect --mode support --gateway auto
HermesConnector connect --mode support --disconnect-after 60
HermesConnector connect --mode resident --gateway auto
HermesConnector autostart enable --confirm
HermesConnector autostart status
HermesConnector autostart disable
HermesConnector revoke
```

`--install` calls the OS's package manager with explicit interactive approval;
it does not grant remote command privileges. The optional server package might
start sshd and expose TCP/22 depending on distribution, which is why the tool
prints the warning and requires confirmation. Ordinary use does NOT need SSH
Server. macOS OpenSSH is normally built-in and the tool does not turn on Remote
Login. Server installation remains distro-dependent and needs real-world
verification before release.

## Limitations / outstanding acceptance

1. Unix GUI/tray is present in the development source but not yet physically
   accepted on real Linux/macOS desktops, including Wayland, menu-bar controls
   and installer UAC/polkit flow. Self-update and signed/notarized binaries
   remain incomplete.
2. No production resident broker on GR2; until installed with owner approval,
   `requested_mode=resident` and unlimited approval are not supported there.
3. On Unix the native system keyring may require an interactive login. Do not
   claim pre-login or after-logout access without a dedicated, consented
   headless credential store and appropriate service identity.
4. Test production-like loss and return of Internet, computer sleep/wake,
   reboot, actual user-context remote command, and live revoke with consenting
   users. Local unit tests/CI packages alone are not acceptance.
5. The current user agent is powerful: once explicitly approved, an operator
   authorized at Gate can execute commands within the approved Unix account.
   Keep its trust boundary, audit, keyring and revoke functionality intact.
