# GR2 / LV1 — controlled scoped revocation deployment

Status: PREPARED ONLY, NOT INSTALLED. Owner must explicitly authorize the
root-owned helper, one restricted sudoers rule, broker code update and broker
restart on LV1. Do not modify VPN (Xray), default sshd, or firewall.

## Prepared artifacts

- `server/enrollment/service.py` — close a verified port through the fixed helper
- `server/enrollment/close_scoped_slot.py` — pidfd termination of a verified SSH child
- `server/enrollment/session_guard.py` — strict target validation (existing)
- `ops/hermes-close-slot` — fixed root-owned, input-filtering wrapper
- `ops/hermes-close-slot.sudoers` — sudo permission for **only** that wrapper

## Preflight / backup

1. Verify LV1 service health, valid SSH access, ports, `doctor` status and active sessions.
2. Check `/etc/sudoers.d/hermes-close-slot`, `/usr/local/sbin/hermes-close-slot` and
   `/opt/hermes-enrollment/close_scoped_slot.py` do not already exist; abort if they do.
3. Create a new timestamped root-only directory under `/var/backups/` (0700).
4. Back up current `/opt/hermes-enrollment/*.py`, broker unit/config, SQLite DB
   using SQLite backup API if live, and `authorized_keys` (files 0600); save SHA256.
5. Copy reviewed artifacts using verified SHA256. Target `service.py` and Python
   modules root-owned 0644; wrapper root-owned 0755; sudoers root-owned 0440.
6. Validate `visudo -cf /etc/sudoers.d/hermes-close-slot`, `python3 -m py_compile`,
   broker service unit and `sudo -n -u hermes-bridge sudo -n ... 0` returns 64
   without executing a valid revocation (the last check must run with valid
   command syntax, and may be validated in a dry-run/test fixture beforehand).
7. Restart **only** `hermes-enrollment.service`; check health and journal.

## Acceptance

1. A new isolated test Windows/SSH client enrols and receives an approved slot.
2. Its real reverse tunnel is active and a request reaches the remote endpoint.
3. Invoke the normal ticket revoke endpoint **while the tunnel is still active**.
4. Require HTTP 200 `revoked`, remote listener disappearance, targeted SSH child
   termination, absence of unrelated session interruption, and `doctor: ok`.
5. Verify the VPN ports and existing daemon remain unaffected.

## Rollback

Stop only `hermes-enrollment.service`, restore backed-up broker code and the
previous sudoers/helper state, validate config, restart broker and check health.
Restore SQLite/keys only if a recovery procedure confirms rollback is safe for
active grants; never blindly overwrite live authorizations. Preserve evidence.

## Known limits

This change does not install the Windows preview nor automatically migrate
already approved GR1/DE2 tickets. GR1-to-GR2 failover for a **new** registration
is implemented in the preview. Existing authorizations remain pinned to their
original Gate until explicitly revoked, expired and verified, or safely handled
through a separately approved emergency recovery procedure.
