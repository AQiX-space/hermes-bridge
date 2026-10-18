# Windows Connector 0.2.4 — broker deployment (DE2)

**Status:** staged; do not execute without the owner's separate approval for this specific production change.
**Scope:** only `/opt/hermes-enrollment/service.py`, new `/opt/hermes-enrollment/session_guard.py`, and the existing enrollment service restart. Do **not** modify nginx, SSH gateway daemon, VPN, firewall, or existing authorizations during this operation.

## Preconditions (read-only)

- `git status` clean, Windows build+broker CI green, packaged SHA256 verified.
- Confirm three units active: `nginx`, `hermes-enrollment.service`, `hermes-bridge-sshd.service`; inspect current approved/pending counts and 23000–24999 listeners.
- Check Linux supports `os.pidfd_open` and `signal.pidfd_send_signal`; check `hermes-bridge` user can inspect its SSH child process cgroup.
- Record current SHA256 of `/opt/hermes-enrollment/service.py` and current installed `session_guard.py` (if present).
- Check file rights and available free disk space. **Do not revoke or kill legacy device sessions during deployment.**

## Deployment (requires separately approved change)

1. Copy both reviewed files to uniquely named staging paths on DE2, verify SHA256 matching reviewed commit. No keys/tickets transferred.
2. Record UTC timestamp. Stop only `hermes-enrollment.service`; protect against unhandled failure with rollback.
3. Take timestamped, mode-preserving backups of original `service.py` and `session_guard.py` if it exists; use `sqlite3.Connection.backup` (or cold copy while service stopped) for requests DB, plus `authorized_keys` snapshot. Keep restrictive permissions; no backups in Git or release assets.
4. Install `service.py` and `session_guard.py` in the same approved directory, owner `root`, mode `0644`, and run `python3 -m py_compile` under a writable controlled location (or `ast.parse` without writing `.pyc`).
5. Start enrollment service; check `systemctl is-active`, `journalctl` for import exceptions, and read-only CLI `pending`/`doctor`. Verify HTTPS POST+GET on **new throwaway test request**, cancel it with `/revoke`, ensure no permanent key added. Check existing VPN and SSH daemon unchanged.
6. Compare approved and active port counts against pre-state; **do not auto-clean** the observed unmatched scoped key without a separate owner's approval.

## Rollback

Stop `hermes-enrollment.service`; restore both exact backed-up source files and a **compatible** DB snapshot if a migration rollback requires it; restore `authorized_keys` only if this deployment modified it (avoid overwriting unrelated legitimate grants after backup); start and smoke test the old service. Do not blindly revert a DB after users have submitted new tickets; reconcile before rollback.

## Required E2E acceptance before enabling automatic session expiration

- New approval from a Windows Connector, real reverse listener and operator SSH authentication.
- Press Disconnect and verify API `revoked`, exact scoped key removed, reverse listener closes, and pre-existing operator SSH session loses access.
- Try reconnect without new approval: must fail.
- Simulated Gate network fault: Connector must block reuse and show pending revocation; background reaper eventually finishes.
- Two devices with common public IP must not affect each other's access.
- Test a deliberate lease expiration only for a **new test device**, never a legacy production permission.

## Current known risks

- Existing production DB has four approved devices without live ports, plus one **unmatched scoped key**. Legacy permissions are not to be removed automatically as part of this code deployment.
- Authenticode publisher signature is unavailable for Windows release; keep 0.2.4 draft until explicit release approval and E2E testing.
- A real SSHd child kill has only been tested in a scoped Linux test harness, not a live production connection.
