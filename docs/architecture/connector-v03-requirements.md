# Hermes Connector 0.3 — owner specification and acceptance matrix

Owner update: 2026-11-23. This is the **original requested outcome**, not a reduction to a CI build or prototype.

## Product behavior

Hermes Connector must be sufficient by itself for remote assistance. No separate
manual downloads from `aqix.ru/me`, manually created remote Windows users or
manually configured SSH for ordinary user-context operation. The application
runs commands with the **exact OS token of the person who launched it**.
A distinct, opt-in alternative-account mode may be added but must never
silently replace the current-user mode.

On supported OSes the Connector checks native OpenSSH Client and Server,
helps provision missing packages with OS-native tools, requests elevation
only for OS-level package operations, validates installed state and never
silently starts a listening SSH daemon or adds a firewall exception.
Current-user mode needs OpenSSH Client transport only; Server is an optional
advanced capability.

Two explicit modes:
- **Support:** launched on demand, starts an approved Gate tunnel, stays up
  indefinitely while the opt-in auto-disconnect checkbox is clear and the
  approved lease permits it; if set, disconnect after user-selected duration.
- **Resident:** explicit opt-in auto-install and autostart, tray-first UI,
  minimal settings, reconnect on transport failure, no idle timeout. New
  enrollment requires human approval and explicitly unlimited lease on Gate.
  Disabling local startup is always available even if Gate is down; this
  does not claim server authorization has been revoked.

The journal is collapsed by default, expandable and copyable. It must retain
relevant actions, decisions and errors with bounded memory and no secrets.
Tray always offers Exit. GR1 / GR2 availability is checked for **new**
registrations; an existing approval is pinned to its original Gate and not
silently transferred.

## Server-side security invariant

`requested_mode` and `requested_lease_seconds` are **untrusted requests**,
not grants. The operator must confirm the actual duration. If the requested
lease differs from the proposed grant, the broker refuses approval rather
than silently substituting the 7200-second default. A zero-second duration
means unlimited until explicit revoke and is not allowed merely because a
client requested it; operator must pass `--ttl-seconds 0` explicitly.

## Implemented in development branch (not production)

| Requirement | Source | Test | Status |
|---|---|---|---|
| Current user token command execution | `src/UserSessionAgent.cs` | Windows identity and HMAC anti-replay tests | CI verified; live operator E2E pending |
| GR1/GR2 enrollment and failover | `src/EnrollmentClient.cs`, `src/Program.cs` | Existing Windows gateway tests | CI verified for new enrollment |
| Native Windows Client and Server feature installation | `src/OpenSshComponents.cs` | Capability command construction | CI verifies commands; actual UAC/install pending |
| User-scoped auto-start | `src/WindowsStartup.cs` | HKCU enable/disable test | CI verified, live reboot/login pending |
| Support/resident preferences | `src/ConnectorPreferences.cs` | Persistence and idle timeout tests | CI verified |
| Backoff and reconnect on broken tunnel | `src/ReconnectPolicy.cs` | Retry sequence tests | CI verified; live outage and restore pending |
| Requested session lifetime on Gate | `server/enrollment/service.py` | SQLite migration, mode/lease tests | CI verified; GR2 deployment pending owner approval |
| Expandable bounded activity journal | `src/Program.cs` | Windows compile | GUI inspection and accessibility testing pending |
| Never silently impersonate different user | `src/UserSessionAgent.cs` | Same-token command test | CI verified |
| Offline/unavailable Gate local disable | `src/Program.cs` | Windows compile | Live click-through pending |

## Not yet delivered

1. **Linux and macOS installers/applications** with matching GUI/tray,
   secure local credential storage, per-user launch and service management;
   current client is Windows WinForms on .NET Framework, not cross-platform.
2. **Truly always available before OS login / after logout**: HKCU Run starts
   only when the user logs in. A dedicated, explicitly provisioned service
   identity with defined rights and recovery is necessary for unattended
   workstation/server operation. It must not silently use `SYSTEM` or change
   user identity.
3. Full self-contained offline OpenSSH package installation where Windows
   Update/WSUS cannot supply optional capabilities; native Windows servicing
   path exists but needs a verified and licensed package fallback.
4. Operator-selectable other-account execution mode; current implementation
   deliberately refuses implicit account switching.
5. GR2 production upgrade for lease negotiation, operator helper and safe
   revocation of active tunnel. No production deployment performed under this
   branch; use backup/rollback and explicit owner approval.
6. **Real high-availability across independent Gate failures for resident**:
   the client currently re-establishes its approved Gate tunnel, but cannot
   automatically move a live grant to the other broker. Full HA requires
   independently approved, revocable registrations on GR1 and GR2 with a
   defined conflict/replay/identity policy and operator location awareness.
   The existing GR1->GR2 chooser applies only when opening a new enrollment.
7. Signed release with Authenticode, Windows and cross-platform UI E2E,
   real account isolation tests, full failover and revoke, long-run reconnect
   tests including sleep/wake, reboot, closed session and disabled network.

## Minimum acceptance scenarios

- On a clean supported OS, user runs the **single** product package, is guided
  to install SSH as needed, approves enrollment, and the remote command prints
  the same account as the Connector process.
- With auto-disconnect OFF, leave the system idle at least 3 hours and confirm
  approved access stays valid. With auto-disconnect ON, verify revocation at the
  requested limit. No hidden 7200-second server default is accepted.
- With resident mode, verify consent, auto-start after login, tray-only UI,
  disconnect/reconnect while the network is unavailable, and disable startup
  without server connectivity. Verify permissions are not escalated.
- For genuine headless 24/7 requirements, test service identity, operation
  after logout and before login, power-loss recovery and remote revocation.

A successful GitHub Actions run is **not** sufficient proof of acceptance.
