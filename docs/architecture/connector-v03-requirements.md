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

## Client implemented in development; server deployment status tracked below

| Requirement | Source | Test | Status |
|---|---|---|---|
| Current user token command execution | `src/UserSessionAgent.cs` | Windows identity and HMAC anti-replay tests | CI verified; live operator E2E pending |
| GR1/GR2 enrollment and failover | `src/EnrollmentClient.cs`, `src/Program.cs` | Existing Windows gateway tests | CI verified for new enrollment |
| Native Windows Client and Server feature installation | `src/OpenSshComponents.cs` | Capability command construction | CI verifies commands; actual UAC/install pending |
| User-scoped auto-start | `src/WindowsStartup.cs` | HKCU enable/disable test | CI verified, live reboot/login pending |
| Support/resident preferences | `src/ConnectorPreferences.cs` | Persistence and idle timeout tests | CI verified |
| Backoff and reconnect on broken tunnel | `src/ReconnectPolicy.cs` | Retry sequence tests | CI verified; live outage and restore pending |
| Requested session lifetime on Gate | `server/enrollment/service.py` | SQLite migration, mode/lease tests | CI verified; broker GR2 deployed and tested 2026-11-26 |
| Expandable persistent, sanitized 512-KiB activity journal | `src/Program.cs`, `src/ActivityJournal.cs` | Windows journal rollover, persistence and secret-redaction tests | CI verified; live GUI acceptance pending |
| Never silently impersonate different user | `src/UserSessionAgent.cs` | Same-token command test | CI verified |
| Offline/unavailable Gate local disable | `src/Program.cs` | Windows compile | Live click-through pending |
| One running instance per Windows profile | `src/SingleInstanceGate.cs` | Windows named mutex tests | CI verified; manual simultaneous-launch check pending |

## Verification checkpoint — 2026-11-23

- `feat/connector-persistent-20261123` development build from commit `d99b390ffa34eed7641e91a83b7dba1858e5593e`.
- Windows/Linux CI run `45255126246` **success**; includes persistent activity journal and one-instance tests.
- PE32 .NET Framework Windows GUI produced as private GitHub Actions artifact `HermesConnector-0.3.0-dev-Windows-unsigned`, retention 7 days.
- Exact build SHA256: `5398df136be80ef5665a850eb02b42fac44f116bb91ec860ca7eb8aed7cdb660`.
- That SHA256 was verified on AlexHUB and Windows Defender returned `found no threats`, exit 0, not `skipped`. The temporary test file was deleted. This does not constitute the product being installed or accepted on the operator's interactive desktop.
- No changes made to the live broker/Gate on LV1, DNS, VPN, installed Windows Connector or stable GitHub release. The branch remains an unsigned development build.

## Verification checkpoint — 2026-11-24 (development only)

- `feat/connector-persistent-20261123`: bounded SSH connect (`ConnectTimeout=10`, `ConnectionAttempts=1`), forward failures and keepalive (`ServerAliveInterval=30`, `ServerAliveCountMax=3`) share one implementation in main connection and diagnostic probe.
- Windows OpenSSH option parsing (`ssh -G`) verified on AlexHUB; Windows CI for this change: `45333884706` PASS.
- OpenSSH Server installer now warns that Windows may briefly enable an inbound firewall rule and disables **only a newly created** `OpenSSH-Server-In-TCP` rule; does not stop/modify previously existing `sshd`. Windows mocked install tests (no system modification): CI `45335491848` PASS.
- Dev EXE from CI `45333884706` SHA256 `a843c8255de3dcb19dc2d2f9cc41c404f7eed29645a2bdd56a0ed7d92503dd1f` was checked on AlexHUB; Defender `found no threats` and exit 0; test copy removed. This is not installed in the user session or signed.
- Live GR2 (LV1) `doctor.ok=true` but uses old schema without `requested_mode` or `requested_lease_seconds`. Synthetic regression on the observed 12-column schema PASS (`server/enrollment/test_live_schema_migration.py`). Production deployment and live resident authorization are NOT approved; runbook `ops/LV1-RESIDENT-LEASE-DEPLOY.md` prepared only.

## Verification checkpoint — 2026-11-26

- **Live LV1 verified again:** `hermes-enrollment.service`, `hermes-bridge-sshd.service`, `hermes-close-slot.socket`, Nginx all active; broker SHA256 `143aa40d133cd4bb6547aeff782ccb510f49c035cb774e8cab8905caef4d5ac2`; socket helper SHA256 `407e49d5eec6b30ee017f473e5306109fbd0e261179aef65dc71ee86fc1d5818`. `NoNewPrivileges=yes`; DB contains `requested_mode`/`requested_lease_seconds`; `doctor.ok=true`, **one existing approved authorization**, zero revoking. Existing authorization was not altered.
- Real live resident enrollment, explicitly unlimited approval, reverse SSH, immediate socket-scoped revoke HTTP 200 and listener removal were already recorded and passed on 2026-11-26. Do not repeat a destructive test on another customer's granted port.
- Test regression after replacing sudo with AF_UNIX helper was fixed in `tools/test_session_closer_linux.py`: isolated CI must fail closed if production socket is absent. Windows + Linux CI run `45883522997` **success**.
- Fixed mislabelled Windows 0.3 EXE: previously assembly metadata and `VERSION` still claimed `0.2.9` while GUI claimed 0.3. Current candidate is `0.3.0-beta.0`; version ordering and EXE metadata regression passed Windows CI `45885203196`.
- Exact Windows candidate SHA256: `1c086bcc597f15fb13f7282fe05d0b2e7d6e94dc28364d09f57db34009cee52d`. Independently verified on ALEXHUB; Windows Defender `found no threats` (exit 0, not skipped). Staged in an ACL-protected, read-only-to-users folder `C:\ProgramData\HermesConnector\staging-v0.3.0-beta.0\HermesConnector-0.3.0-beta.0.exe`. **Not launched under Alex or installed.** The previous `C:\Users\Alex\AppData\Local\HermesBridge\HermesConnector.exe` remains unchanged at 0.2.9; no Connector process was running at inspection.
- Final Windows approval still requires the real user **Alex** to launch this preview, confirm enrollment and an operator HMAC command with `whoami` under Alex, then verify idle, stop, revoke, start after login and rollback. Technical SSH user `aqixssh` is **not** a substitute for this test.
- This branch and the production Gate are not a signed stable release. Do not publish a public prerelease to all existing 0.2.9 updater clients before controlled end-user acceptance.

## UAC current-user support — 2026-11-27 development

- UAC only by explicit click; normal diagnostics and resident mode stay unprivileged by default. UI shows identity/elevation. Same-SID warm tunnel handoff reuses the already-approved Gate ticket; cancellation should leave the old connection active.
- New test suite: `tests/ElevationSupportTests.cs`; version `0.3.0-beta.1`. Operational and acceptance details: `docs/architecture/uac-elevation-mode.md`.
- **Not yet accepted on live interactive ALEXHUB**; do not confuse CI with UAC GUI verification.

## Self-update and resident PIN — 2026-11-27 development

- Beta.2 fixes the resident tray lock: double-click/Open prompts PIN, correct PIN restores full support UI and disables resident autostart without dropping the current approved tunnel. PIN may be changed; defaults to `1111`, with DPAPI/PBKDF2 and persistent rate-limit. See `docs/architecture/tray-pin-access.md`. A local user can still disconnect/exit to withdraw remote-access consent.
- Beta.2 stages and automatically applies valid GitHub Release updates during active sessions, then uses the verified rollback helper and reconnects with the old approved ticket. See `docs/architecture/automatic-updates.md`. This is NOT a signed public release or a proven live GUI rollout; current 0.3.0-beta.0 binaries cannot gain this feature without a trusted one-time upgrade.

## Not yet delivered

1. **Linux/macOS end-user acceptance:** four unsigned PyInstaller packages (Linux
   x64/ARM64, macOS Intel/Apple Silicon) and a development Tk/tray UI were built
   and tested in CI, including signed current-user commands through an isolated
   real `ssh -R`. Physical desktop/install/reboot checks, signing/notarization
   and self-update are still outstanding.
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
5. **GR2 already deployed on 2026-11-26:** reviewed broker, resident lease
   negotiation and protected socket-activated live revocation passed E2E.
   See `ops/LV1-ROOT-SOCKET-REVOKE-DEPLOY.md`. Still outstanding: verify client
   0.3 on the actual interactive `Alex` desktop, continuous idle soak and
   reconnect after changing networks; protect currently active approvals.
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
