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

## Observed deployment / incident — 2026-11-26

- Owner approval was given in this conversation for the scoped LV1 broker/helper rollout; this section is a **verified as-built** record, not a general authorization for unrelated work.
- Backup: `/var/backups/hermes-lv1-20261126TaqSJKP`, root-only mode 0700, SQLite backup 12 records / `integrity_check=ok`; never publish its contents.
- First cutover attempt checked SQLite columns immediately after systemd restart before the broker finished startup. It triggered rollback. The original rollback mistakenly used `cp -a` from a backup file chmodded 0600, making restored `service.py` unreadable by service user; broker was temporarily unavailable. This was corrected with `install -m 0644 -o root -g root` and restart; `doctor.ok=true`, external TLS 200 and Nginx/VPN were verified. **Do not use cp -a to restore broker code from the root-only backup.**
- Second cutover waited for **real HTTP 404** at `http://127.0.0.1:18511/v1/enroll/hermes-unregistered-probe` before checking new columns. `requested_mode` and `requested_lease_seconds` appeared, SQLite intact, 12 historical records retained.
- Production SHA256: `service.py` `143aa40d133cd4bb6547aeff782ccb510f49c035cb774e8cab8905caef4d5ac2`, `close_scoped_socket.py` `407e49d5eec6b30ee017f473e5306109fbd0e261179aef65dc71ee86fc1d5818`. Socket unit `50b20dc6fe690989eee24c5fa230d2bcea75e5f2a97287911c5fff695fe9011b`; template service `30d9f46f864e721a56e0f8a759c8fc98cb46b7ce6d1308fe38a721d085a58e74`. Broker `NoNewPrivileges=yes` remained intact.
- Untrusted call from an independent `hermes-bridge` shell failed `untrusted_broker_peer`. Fully active resident test on GR2: HTTP 202 enrollment, explicit operator `--ttl-seconds 0`, approved slot 23000, reverse SSH forwarded real HTTP response, **live HTTP revoke 200**, tunnel exited, listener disappeared. Reproducible test in `tests/e2e/lv1_resident_revoke_smoke.py --confirm-live-lv1`, **not for automatic CI**.
- Last health: `doctor.ok=true`, zero approved/revoking and zero active test sessions, nginx/Gate/socket active, `remnanode` and unrelated VPN containers unchanged. Full Windows GUI 0.3 acceptance and multi-hour resident idle soak remain pending.
