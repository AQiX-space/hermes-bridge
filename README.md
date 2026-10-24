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

## Offline registration packet (developer preview)

`python3 server/enroll.py --device pc1 --host bridge.example.com --port 22471 --slot 22473 --public-key-file pc1.pub --gateway-host-key-file gateway.pub --output-dir ./out` generates `pc1.bridge` and prints the server-side `authorized_keys` entry. The operator must manually approve device ownership and install the entry; the tool deliberately does **not** modify a server, open a port, or authenticate a device automatically. On Windows use **Импорт параметров оператора** to apply that `.bridge` file and pin the SSH server host key. Obtain the bundle through a trusted channel: the format is not cryptographically signed. No unattended enrollment or updater yet.

## Updates UI (interim)

The **Проверить обновления** control currently opens the repository's private GitHub release page in the system browser; it prominently states that automatic updates are *not enabled*. It is **not** a silent updater. Future auto-updates require authenticated server-side artifact distribution, verified signatures, and a rollback-capable installer; direct access tokens are never bundled with the EXE.

## Safety gate — 2026-10-11

Automatic publication of unsigned binaries is **disabled** after Microsoft Defender flagged an earlier developer executable as `Trojan:Win32/Wacatac.B!ml` on an AQiX host. A clean CI build is not an antivirus clearance. Do not disable Defender or whitelist this binary. Subsequent CI runs validate source compilation and enrollment tests only. Shipping resumes after security review, signed builds and independent validation on Windows. Earlier preview releases are archived testing artifacts, **not production-approved**.

The UI only reports that an `ssh.exe` client process exists; this does **not** verify that an operator can reach the device. A server-side session status API and verified end-to-end test remain required.

## Signed automatic update client implementation

Client now implements manual `Проверить обновления` plus background update availability checks every six hours. HTTPS manifest: `https://updates.aqix.ru/hermes-bridge/stable.json`. The signed fields are `version`, `url`, `sha256`, verified using the RSA-3072 public key built into `UpdateClient.cs`. Staged bytes are SHA-256 checked. A separate updater process embedded as a resource swaps the file after the main app exits, saves `.previous`, and restores it on failure. Sessions are not interrupted without explicit confirmation; updates require Bridge to be stopped. Neither GitHub credentials nor the release private signing key are bundled.

**Not yet live:** the update HTTPS hostname still routes to another server and DE2's current HTTPS certificate is self-signed. The endpoint must first be configured with a trusted certificate and tested end to end. Moreover, Defender flagged prior unsigned builds; the release pipeline remains in build-only mode until malware review, Authenticode signing, and acceptance testing. No release is promoted automatically.

## Versioning

Version contract: `MAJOR.MINOR.PATCH` for stable builds and `MAJOR.MINOR.PATCH-beta.N` for prereleases. The current preview is `0.2.0-beta.1` (Windows assembly file version `0.2.0.0`). Private GitHub build commits and cryptographic SHA hashes must never be used as human-facing product version numbers. The signed update manifest uses Windows `System.Version` (`0.2.0.0`) until a prerelease comparator is added; the beta channel is separate from stable.

## 0.2.0-beta.3 automatic update behavior

With a disconnected support session, the client checks the signed beta manifest immediately on launch and then every six hours. If a newer correctly signed version is found, it downloads the pinned HTTPS binary, verifies SHA-256 and installs via an embedded helper with a rollback backup. An active support session is never interrupted; manual checking is also available. Invalid TLS, an unreachable mirror, or a bad signature must fail closed. This functionality requires a **live, correctly routed HTTPS update mirror**; the current external DNS/network mismatch means automatic delivery is not yet operational. No automatic release promotion or code-signing bypass is implemented.

## OpenSSH Server preflight (0.2.5, source-only until release acceptance)

The Windows GUI checks BOTH the local OpenSSH Client executable and the Windows `sshd` service. A verified `SSH-2.0-` banner must be returned by `127.0.0.1:22` before a registration request is submitted or an approved reverse SSH tunnel is started. A periodic local check removes the connected indicator if `sshd` stops. An acknowledged reverse port is not equivalent to an authenticated operator login.

If OpenSSH Client or Server is absent, users on Windows 10 (build 1809)+ or Windows Server 2019+ may explicitly install the *matching Microsoft Windows Optional Capability* via `Add-WindowsCapability`; the feature download uses Windows Update or their organization's configured Feature-on-Demand source. UAC consent is mandatory and the result is rechecked. The Connector does **not** start/enable the `sshd` service, overwrite `sshd_config`, or add a firewall rule itself. Windows may automatically create an inbound TCP/22 firewall rule during feature installation: the confirmation warns users to inspect the rule and SSH listen addresses before manually starting the service. On unsupported Windows releases, there is no arbitrary third-party binary download or unsafe fallback. Offline/WSUS installations require an administrator-provided matching Features-on-Demand source.

This change requires Windows CI tests and real Windows GUI/connection smoke tests before shipping. Server-side one-hour enrollment lease settings are separate and are not changed by this client patch.
