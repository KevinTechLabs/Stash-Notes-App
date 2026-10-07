# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems.

Report it privately through GitHub instead:
<https://github.com/KevinTechLabs/Stash-Notes-App/security/advisories/new>
(**Security → Report a vulnerability**). Include what you found, how to
reproduce it, and what an attacker could do with it. You'll get a reply within
a few days. Please allow up to 90 days for a fix before disclosing the issue
publicly.

If you spot something in this repository that looks like a real credential,
token, address or other private detail, please report it the same way.

## Supported versions

Only **Stash v2** (`v2/`) on `main` is supported. Stash v1 (`app.py`) is kept for project history and no longer receives fixes.

## What's already in place

- Logins are encrypted on the device with AES-256-GCM before they are saved; the server only serves the app's files.
- The key is derived from the master password with PBKDF2-HMAC-SHA256 (600,000 rounds), and the master password must be at least 12 characters.
- The app locks automatically after 5 minutes idle and can be locked manually.
- Backups are encrypted, and access is over HTTPS through Tailscale.
- Stash is a personal notes app, not a replacement for an audited password manager.
