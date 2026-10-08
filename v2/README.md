# Stash v2

Stash v2 is a self-hosted password manager built as a self-contained, installable web app (PWA). It is plain HTML, CSS and JavaScript with no build step and no backend. All encryption happens in the browser using the Web Crypto API and a bundled Argon2 module, and logins are stored encrypted on the device. The app loads nothing from other websites.

## Files

```text
v2/
├── index.html            # the interface and its security policy
├── app.js                # app logic and encryption
├── vendor/               # Argon2 (argon2-browser, MIT): argon2.js, argon2-glue.js, argon2.wasm
├── manifest.json         # name, icons and colors for "Add to Home Screen"
├── sw.js                 # service worker: caches the app so it works offline
├── icon-192.png          # app icons
├── icon-512.png
├── icon-maskable-512.png # Android adaptive icon
└── apple-touch-icon.png  # iPhone home screen icon
```

## Hosting with Tailscale

Stash must be served over **HTTPS**. Browsers only allow Web Crypto and app installation on secure origins. Tailscale Serve provides HTTPS on the tailnet with no extra software.

1. In the Tailscale admin console, open **DNS** and enable **MagicDNS** and **HTTPS Certificates**.
2. Copy the `v2/` folder to the server, for example to `~/Documents/stash-v2`.
3. Serve it. HTTPS sharing is allowed on ports 443, 8443 and 10000. This uses 10000 so it can sit alongside v1 on 443:

   ```bash
   sudo tailscale serve --https=10000 --bg /home/<user>/Documents/stash-v2
   ```

4. Print the URL:

   ```bash
   tailscale status --json | python3 -c "import sys,json;print('https://'+json.load(sys.stdin)['Self']['DNSName'].rstrip('.')+':10000/')"
   ```

5. On the phone, connect Tailscale, open the URL, and add it to the home screen:
   - **iPhone:** Safari → Share → Add to Home Screen
   - **Android:** Chrome → ⋮ → Install app

Check or stop the share:

```bash
sudo tailscale serve status
sudo tailscale serve --https=10000 off
```

If UFW is enabled, the Tailscale interface must be allowed (`sudo ufw allow in on tailscale0`).

### Updating

Replace the files in the served folder, then open the app with Tailscale connected. The service worker picks up the new version. Bump the `CACHE` name in `sw.js` when releasing changes so cached files are refreshed.

## Security design

### Keys

- A random **256-bit data key** encrypts the list of logins with **AES-256-GCM**. A fresh random IV is used on every save.
- The data key is stored twice, each copy encrypted (wrapped) with AES-256-GCM:
  - once with a key derived from the **master password**
  - once with a key derived from the **recovery code**
- The master-password key uses **Argon2id** (RFC 9106) with **64 MiB of memory, 3 passes** and a random 16-byte salt. Every guess costs that much memory and time, which makes guessing on GPUs or custom hardware far slower than with PBKDF2. The bundled module is checked against the RFC 9106 test vector.
- The recovery-code key uses **PBKDF2-HMAC-SHA256** with **600,000 rounds**. The code already has 120 bits of randomness, so a slower function would add nothing.
- Changing the master password only re-wraps the data key; the logins and recovery code are unaffected.

### Master password and recovery code

- The master password must be at least **12 characters**. It is never stored.
- The recovery code is 24 characters from a 32-character alphabet (120 bits of randomness), shown once at setup. It can be replaced from Settings, which makes the old code stop working.
- A forgotten master password can be reset with the recovery code. If both are lost, the logins cannot be recovered by anyone.

### Storage

- The encrypted vault is saved in the browser's `localStorage` on the device, under the key `stash.v2.vault`. Nothing is sent to the server.
- On iPhone, a home screen app has its own storage, separate from Safari. Removing the app from the home screen deletes its data, so save a backup first.

### Backups

- **Settings → Save encrypted backup** exports the vault as a `.json` file. It is the same encrypted data, so it opens only with the master password or recovery code that was current when it was saved.
- **Settings → Restore from backup** replaces the vault on the device with a backup file.

### Locking

- Stash locks **as soon as it leaves the screen** (switching apps, going home, locking the phone). Exceptions: while a file picker or share sheet Stash opened is showing, while the recovery code is on screen, and while a login is being edited, where there are 60 seconds to copy something from another app.
- It also locks after 5 minutes of inactivity, and on demand with the lock button.
- When locked, the decrypted logins and keys are cleared from memory.

### Wrong-attempt delay

- After 5 wrong master passwords or recovery codes, Stash makes you wait 30 seconds, doubling with each further miss up to 15 minutes. The counter survives reloads and resets after a successful unlock.
- This slows down guessing on the phone itself. Someone who copies the encrypted data off the phone isn't limited by it, which is what Argon2id is for.

### No outside content

- A strict Content Security Policy only allows the app's own files: no outside scripts, fonts, images or connections, no plugins, and no form submissions. This blocks injected code from loading anything or sending your data anywhere.
- Text uses the phone's built-in system fonts instead of downloaded ones.
- The offline cache only stores Stash's own files and always fetches fresh copies when online, so an update never mixes old and new files.

### Clipboard and screen

- Copied passwords and recovery codes are wiped from the clipboard after 30 seconds, and when Stash locks. Browsers only allow this while Stash is open, so if you switch away first, the wipe happens as soon as you come back.
- A revealed password hides itself again after 20 seconds.

### 2FA codes

- A login can store a 2FA setup key (base32) or an `otpauth://totp/...` link. Stash generates the time-based code (TOTP, RFC 6238) on the device with the Web Crypto API; SHA-1, SHA-256 and SHA-512, 6–8 digits and custom periods are supported.
- The key is saved inside the encrypted vault like every other field, and copied codes are cleared from the clipboard after 30 seconds.
- Keeping a site's password and its 2FA key in the same vault is convenient, but it means anyone who unlocks Stash has both. For your most important accounts, especially your email and any other password manager, consider keeping their 2FA in a separate authenticator app.

### Upgrades from earlier v2 data

Data saved by earlier v2 builds (PBKDF2, 310,000 or 600,000 rounds) still opens, as do backups made with them. On the next unlock the master-password key is re-wrapped with Argon2id automatically, and the recovery-code key is re-wrapped the next time the recovery code is used. Existing master passwords shorter than 12 characters still unlock, and Stash shows a reminder to change them.

### Limitations

Stash is a personal project and has not been independently audited. Anyone who controls the server's copy of these files controls the app code the phone loads, so keep the server secure, and see [`docs/MONITORING.md`](../docs/MONITORING.md) for alerting on any change to them. For the most sensitive accounts, use two-factor authentication as well.
