# Stash Notes App

Stash is a small, self-hosted personal notes application built for keeping organized records such as account usernames, passwords, categories, and notes. It is intentionally a **notes app**, not a full password-manager replacement.

Because Stash can contain real credentials, the deployed version includes encryption, authentication, session isolation, automatic locking, HTTPS access through Tailscale, firewall hardening, and encrypted backups.

## Stash v2 at a glance

<table>
<tr>
<td align="center"><strong>Unlock</strong></td>
<td align="center"><strong>Logins</strong></td>
<td align="center"><strong>Login details</strong></td>
<td align="center"><strong>New login</strong></td>
<td align="center"><strong>Recovery code</strong></td>
</tr>
<tr>
<td align="center"><img src="docs/images/v2-unlock.png" width="160" alt="Stash v2 unlock screen"></td>
<td align="center"><img src="docs/images/v2-home.png" width="160" alt="Stash v2 login list"></td>
<td align="center"><img src="docs/images/v2-login-detail.png" width="160" alt="Stash v2 login details"></td>
<td align="center"><img src="docs/images/v2-new-login.png" width="160" alt="Stash v2 new login form with password generator"></td>
<td align="center"><img src="docs/images/v2-recovery-code.png" width="160" alt="Stash v2 recovery code screen"></td>
</tr>
</table>

<sub>Screenshots use made-up sample data.</sub>

## Versions

| | **Stash v2** (latest) | **Stash v1** (original) |
|---|---|---|
| Location in repo | [`v2/`](v2/) | [`v1/`](v1/) |
| Type | Installable phone app (PWA) | Flask web app on the server |
| Where logins are stored | Encrypted on the phone itself | Encrypted in SQLite on the server |
| Encryption | AES-256-GCM | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 rounds | PBKDF2-HMAC-SHA256, 600,000 rounds |
| Minimum master password | 12 characters | 12 characters |
| Forgot master password | Reset with a recovery code | Not supported |
| Works offline | Yes | No |
| Backups | Encrypted backup file from inside the app | Manual GPG-encrypted archive |
| Auto-lock | 5 minutes idle + manual lock | 15 minutes + manual lock |
| Hosting | Static files via `tailscale serve` (no Python needed) | Gunicorn + systemd + Tailscale Serve |

v1 is kept in this repository unchanged so the project history shows how Stash evolved.

# Stash v2

Stash v2 is a rebuild of Stash as an installable phone app. It adds to the home screen with its own icon, opens full screen, works offline, and keeps every login encrypted on the device. The server only hands out the app's files; it never sees or stores your logins.

### What's new in v2

- **Installable app:** add to the home screen on iPhone or Android; runs full screen with its own icon.
- **On-device encryption:** logins are encrypted with AES-256-GCM before they are saved, using a key protected by your master password.
- **Recovery codes:** a 24-character recovery code can reset a forgotten master password without losing any logins.
- **Works offline:** after the first install, Stash opens without a network connection.
- **Password generator** with a strength meter, and a warning dot on weak saved passwords.
- **Folders:** Personal, Gaming, Shopping, Social Media, Banking, Homelab and Other, with filter chips.
- **Search** across sites, usernames, websites, notes and folders.
- **One-tap copy** for usernames and passwords.
- **Encrypted backups** that open with either the master password or the recovery code.
- **Redesigned dark interface.**

See [`v2/README.md`](v2/README.md) for setup and the security design, and [`CHANGELOG.md`](CHANGELOG.md) for the full list of changes.

---

# Stash v1

The original server-based Flask version, with its screenshots, deployment notes and hardening steps, lives in [`v1/`](v1/). See [`v1/README.md`](v1/README.md).

## Documentation

- [`v2/README.md`](v2/README.md) — Stash v2 setup, hosting with Tailscale, and security design.
- [`v1/README.md`](v1/README.md) — Stash v1 (original Flask version), screenshots and deployment.
- [`CHANGELOG.md`](CHANGELOG.md) — what changed between versions.
- [`docs/SETUP.md`](docs/SETUP.md) — step-by-step deployment and configuration history.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security model, secrets, network exposure, and operational precautions.
- [`docs/BACKUPS.md`](docs/BACKUPS.md) — backup, encryption, verification, and recovery procedures.
