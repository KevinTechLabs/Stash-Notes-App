# Changelog

## v2.0 — Stash v2

A ground-up rebuild of Stash as an installable password manager for your phone. The new version lives in [`v2/`](v2/). v1 is unchanged and remains in the repository root.

### Added

- Installable app (PWA) for iPhone and Android, with its own icon and full-screen display.
- Offline support through a service worker.
- On-device encryption: logins are encrypted with AES-256-GCM in the browser and never sent to the server.
- Recovery codes for resetting a forgotten master password without losing logins.
- Encrypted backup export and restore from inside the app.
- Password generator with a strength meter.
- Weak-password indicator on saved logins.
- Folder filter chips: Personal, Gaming, Shopping, Social Media, Banking, Homelab and Other.
- Search across site, username, website, notes and folder.
- One-tap copy for usernames and passwords; show/hide for passwords.
- Copied passwords and recovery codes are cleared from the clipboard after 30 seconds (and when Stash locks); revealed passwords hide again after 20 seconds.
- Login detail view with a link to open the website.
- Settings for backups, recovery codes, changing the master password and erasing data.
- Redesigned dark interface with A–Z grouped lists.

### Changed

- Architecture moved from a Flask + SQLite server to static files. The server now only hosts the app; it stores no data and needs no Python.
- Encryption moved from Fernet (AES-128-CBC + HMAC) to AES-256-GCM with a wrapped data key.
- Auto-lock shortened from 15 minutes to 5 minutes of inactivity.
- Hosting uses `tailscale serve` directly on a folder (port 10000), alongside v1.

### Kept from v1

- PBKDF2-HMAC-SHA256 with 600,000 rounds for deriving keys from the master password.
- 12-character minimum master password.
- Manual lock button.
- Tailscale-only HTTPS access and UFW firewall setup.

## v1.0 — Stash v1

The original self-hosted Flask version. See the main [`README.md`](README.md) and [`docs/`](docs/).
