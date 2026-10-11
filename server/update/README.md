# Private GitHub -> gateway signed update distribution

The signing key must remain in Zion/secured gateway vault, **never** in GitHub or the Windows binary.

Publishing workflow (after malware review, Authenticode signing, testing):
1. CI builds binaries in private GitHub. A restricted operator retrieves and scans them.
2. Operator signs the approved binary with trusted code-signing certificate.
3. Gateway downloads approved private GitHub asset using a server-only token, never shipped to clients.
4. Publish EXE and `manifest.json` over HTTPS with no sensitive credentials. Manifest values (`version`, `url`, `sha256`) are signed by RSA-2048/3072 PKCS#1 v1.5 SHA256.
5. Client checks RSA signature against pinned public key before fetching; then checks SHA256 and update version before launching updater.
6. Updater performs safe replace + backup/rollback. Updates are applied only while Bridge is stopped.

Server HTTP, TLS and release promotion still need deployment and end-to-end testing. A raw GitHub release is NOT an auto-update channel for untrusted clients.
