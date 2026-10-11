# Hermes Bridge Windows

PRIVATE developer preview. A .NET Framework Windows Forms client for individual, time-limited reverse SSH sessions to the German bridge gateway.

- One EXE, Windows tray, Save / Start / Stop / Reload.
- Each device creates its own SSH Ed25519 identity locally. Only the **public** key is shared during enrollment.
- Operator must register public key, authorize session, and assign unique reverse port. No reusable client credentials in the EXE.
- Explicit pinned gateway host key (`known_hosts`) is required; unknown SSH servers cannot be silently trusted.
- 5–240 minute local TTL and reconnect loop while Start is active; closing window hides to tray, Exit terminates the tunnel.
- Existing Windows OpenSSH Client and Server are required. Server installation and Windows 7 support are future work.
- No auto-update implementation yet. Do not embed GitHub tokens. Signed manifest and relay delivery need implementing before unattended updates.
- This repository is NOT an approved production release and has no enrollment API yet.

The GitHub Actions workflow compiles `src/Program.cs` on a Windows runner and uploads a private build artifact.
