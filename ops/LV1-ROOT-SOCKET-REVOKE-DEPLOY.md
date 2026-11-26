# LV1 restricted revocation with NoNewPrivileges retained — 2026-11-26

Owner authorized the specific rollout of updated Hermes Enrollment Broker plus a scoped SSH revocation helper on LV1 on 2026-11-26. **Do not change VPN, default SSH, nginx, DNS, certificates or firewall.** The older `ops/LV1-REVOKE-HELPER-DEPLOY.md` sudoers method is NOT safe/functional on this host because `hermes-enrollment.service` has `NoNewPrivileges=yes`; **do not install the sudoers helper or remove NoNewPrivileges**.

## Scope and security

- Broker `/opt/hermes-enrollment/service.py` (user `hermes-bridge`, isolated systemd unit unchanged); adds explicit support/resident lease and socket-based scoped revoke.
- Root-owned read-only code `/opt/hermes-enrollment/close_scoped_socket.py` (0600/0644) and pre-existing `/opt/hermes-enrollment/session_guard.py` (unchanged).
- Socket-activated systemd units `/etc/systemd/system/hermes-close-slot.socket` and `/etc/systemd/system/hermes-close-slot@.service`. Local AF_UNIX path `/run/hermes-close-slot.sock`, owner `hermes-bridge`, mode 0600, not exposed to network. Root helper is one-request, constrained to broker UID+`hermes-enrollment.service` cgroup+port 23000..24999+verified `hermes-bridge-sshd.service` process and pidfd; `NoNewPrivileges` remains enabled on BOTH services.

## Before modifying production

1. Check Git status and exact reviewed commit; verify current live hashes and service config, no pending/approved/revoking grants, no unknown listeners; confirm nginx/VPN unaffected.
2. Make a timestamped mode-0700 root backup directory under `/var/backups`. Copy broker code and unit/config, SSH authorized_keys and any existing target unit/helper paths. Back up SQLite with `sqlite3.Connection.backup()` while live, then `PRAGMA integrity_check`. Keep passwords and tickets out of command output and logs.
3. Stage only reviewed artifacts under a new temporary directory and compare hashes. Run `python3 -m py_compile`, `systemd-analyze verify`, preflight check socket unit + service and root-owned source directory. Roll back if any drift or syntax failure.
4. Install ONLY broker `service.py`, `close_scoped_socket.py`, two systemd unit files; do not install sudoers. First enable/start **only** `hermes-close-slot.socket`; verify root service is inactive until a request; then restart **only** `hermes-enrollment.service`.
5. Verify both original service listeners, TLS healthz, new database columns, `doctor`, no prior grants changed, approved and pending request flow. Real E2E scoped revoke while SSH forward active must return 200, release only its own slot. Test `requested_mode=resident` with `requested_lease_seconds=0` and separate operator `--ttl-seconds 0`; no automatic grant.
6. Compare VPN containers/ports and default SSH host-key fingerprint before/after. Capture root-owned backup location, hashes, smoke-test results and Git commit in `KVN/node_registry/nodes/lv1/STATE.md`, `RESTORE.md`, `changes/` and dual memory (Git+Мнемос).

## Rollback

Disable/stop only `hermes-close-slot.socket`; restore previous broker code; restart only `hermes-enrollment.service`. Do not blindly overwrite SQLite: the schema extension is backwards compatible, and new live grants could have appeared. Confirm TLS/SSH & `doctor` and preserve backup/evidence. Restore new units/files only if verified they were installed by this change; never remove pre-existing files. Restore actual authorization data from the SQLite backup only under a separate verified reconciliation (never silently erase grants).

**Known limitation:** no permanent pre-login Windows process without a separately authorized system account/service; GUI 0.3 still needs real Windows acceptance and signed releases. Do not call the whole connector complete from this server rollout.
