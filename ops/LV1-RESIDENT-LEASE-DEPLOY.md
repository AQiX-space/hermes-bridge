# GR2/LV1 — resident enrollment broker cutover (NOT YET APPROVED)

Status: **PREPARED ONLY**. No production commands in this document have been executed. Requires owner approval for **the specific LV1 broker + scoped-revocation helper deployment**. Do not interpret a generic «продолжай» as approval. Do not modify VPN services, default SSH, TCP/443, DNS or shared firewall.

## Verified baseline (read-only on 2026-11-24)

- LV1 `hermes-enrollment.service` and `hermes-bridge-sshd.service`: active.
- Installed broker `/opt/hermes-enrollment/service.py` SHA256: `5f237438bfaddecd0a1383b98bb7954b6942dbdf576d1acbe2a6f68fffbcccc8`.
- Database at `/var/lib/hermes-enrollment/requests.sqlite3` has exactly 12 legacy columns: `ticket, device, key, created, status, slot, config, code, last_seen, expires_at, computer_name, local_ipv4`. It does **not** have `requested_mode` or `requested_lease_seconds`.
- At inspection, `doctor` showed `ok:true`, `approved:0`, `revoking:0`; recheck immediately before changing anything.
- Development broker `server/enrollment/service.py` adds two columns, explicit lease negotiation and `--ttl-seconds 0`; the **same file also depends on a scoped revoke helper**. Installing only `service.py` without the helper would impair live revocation. Use `ops/LV1-REVOKE-HELPER-DEPLOY.md` as part of one reviewed change.

## Preconditions and authorization

1. Owner explicitly approves deployment of the reviewed versioned broker **and** the privilege-separated scoped helper/sudoers on LV1, stating that changing these two Hermes services is acceptable. Do not touch VPN.
2. Verify current Git branch/commit, clean tree, matching signed-off code, current live hashes and no drift. Verify `doctor`, listener state and status of all connected clients. Stop if any conflicting session exists; do not discard registrations.
3. Audit `sudoers` entry `hermes-bridge ALL=(root) NOPASSWD: /usr/local/sbin/hermes-close-slot *` and fixed wrapper's strict port validation; perform a security review before privilege granting. If unsafe, revise and rerun tests before deploying.
4. Confirm the SSH operator route to LV1 and independent console recovery. Schedule a short window and provide rollback owner. No installation from an unaudited CI artifact.

## Backup and exact scope

- Create a timestamped **root-owned 0700** backup folder under `/var/backups/hermes-lv1-*`; record SHA256 of `/opt/hermes-enrollment/*.py`, systemd broker unit, `/etc/ssh/hermes-bridge-sshd_config`, the effective sudoers file (if present), root helper (if present), and `authorized_keys`.
- Back up SQLite by its built-in `Connection.backup()` API while the database is live, not by a blind `.sqlite3` file copy; `PRAGMA integrity_check` on backup must return `ok`. Do not log tickets or keys.
- Do not overwrite pre-existing paths without comparing hashes. Copy only reviewed broker Python modules, `close_scoped_slot.py`, fixed helper and single restricted sudoers rule. Expected ports unchanged: HTTPS 18512, private broker 18511, reverse SSH 22471.
- Run `python3 -m py_compile`, `visudo -cf`, `/usr/sbin/sshd -t -f /etc/ssh/hermes-bridge-sshd_config`, and `systemd-analyze verify`. **Reload/restart only `hermes-enrollment.service`**; no VPN or primary sshd restart.

## Acceptance gates

- Confirm HTTPS `https://gr2.touch01.top:18512/healthz`, broker GET unknown ticket returning 404, SSH host-key fingerprint unchanged, and `doctor.ok=true`.
- Verify the new columns exist; existing approved/pending records (if any) have unchanged status, slot, key and expiry. The synthetic legacy-schema migration regression is `server/enrollment/test_live_schema_migration.py` (already executed without production data).
- Submit a **test** support registration with a finite requested duration and reject operator approval when granted TTL differs. Separately submit a test resident request `requested_mode=resident`, `requested_lease_seconds=0`; operator must pass **explicit** `--ttl-seconds 0`. No silent grant and no auto elevation.
- Open a real test reverse tunnel and authenticated current-user command on a **consenting test Windows account**; verify expected identity and unchanged VPN; stop the tunnel and test **live** revoke 200 and disappearance of the listener. A read-only healthz alone is not acceptance.
- Check service logs and database after the migration, no secrets in logs; verify existing sessions were not interrupted unexpectedly. Test at least one reconnect after network loss, and longer idle-soak (>=3h) for resident mode before stable release.

## Rollback and caveats

- If app or syntax check fails: disable only the newly installed helper sudoers entry, restore previous reviewed broker code and unit from backup, restart broker, verify `doctor`, TLS and SSH; preserve evidence of the failed validation.
- **Do not blindly overwrite the live SQLite DB**: new enrollments or revocations may have happened since the backup. New columns are backward-compatible with the earlier broker; retain the migrated DB unless an explicit reconcile/restore procedure proves safe. On conflicting sessions, stop and request owner direction.
- Do not assume an infinite lease makes the client available after Windows logout: HKCU Run starts on login only. A separate, explicitly authorized service identity and a different headless Windows process are still required for true pre-login unattended operation.

Result until approved and actually tested: **awaiting authorization / not deployed**.
