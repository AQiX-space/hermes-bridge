# Hermes Connector enrollment broker — experimental

An unprivileged localhost-only Python service accepts PUBLIC ED25519 device keys (`POST /v1/enroll`), returns random tickets, and provides polling (`GET /v1/enroll/{ticket}`). Devices remain pending until a trusted local operator explicitly approves. The operator CLI runs in dry-run mode by default; `--apply` is a privileged production write, only after explicit approval for that particular enrollment. It backs up `authorized_keys`, installs per-key `permitlisten` restrictions, and restores the backup if the database update fails. A basic 3-requests/15-minutes per-device rate limit now exists; reverse-proxy per-IP limits, authenticated HTTPS, revocation of live sessions, and production deployment are not yet implemented. Do not expose HTTP listener publicly or treat device registration as permission without operator approval.

Production endpoint on DE2: `https://de2.nod.aqixnet.com:18512/v1/enroll`. Dedicated Nginx 18512 with Lets Encrypt, reverse proxy to localhost 18511; per-IP rate limit; UFW 18512. SSH daemon on 22471 permits localhost reverse listens for approved keys; `authorized_keys` per-device `permitlisten` restriction remains mandatory. Initial approval still requires a trusted operator, not autonomous issuance. GitHub updates remain independent of this endpoint.

## Temporary device operations (operator only)

`service.py --db /var/lib/hermes-enrollment/requests.sqlite3 pending` lists unexpired requests. Approval supports `approve --ticket TICKET --host de2.nod.aqixnet.com --hostkey 'ssh-ed25519 ...' --slot auto` (dry run); adding `--apply` makes an atomic, backed-up change to `authorized_keys`. The server allocates a free slot in 23000–24999. Verify device identity before approving.

`revoke --ticket TICKET` previews removal of a previously approved device; `revoke --ticket TICKET --apply` removes only that device's SSH authorized key, keeps a timestamped backup and marks its registration revoked. **Warning:** this blocks future SSH authentications but does NOT immediately terminate an existing SSH session or revoke a live remote forward. For urgent revocation, also terminate that device's existing SSH session through a separately reviewed operator operation. Do not mistake this command for a full live-session kill switch. Temporary Windows PCs are never a gateway dependency.

Production broker deployment is a separate, owner-approved change: do not assume that a GitHub main branch push updates `/opt/hermes-enrollment/service.py` on DE2.
