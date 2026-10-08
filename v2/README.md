# Stash v2

Stash v2 is a self-hosted password manager built as a self-contained, installable web app (PWA). It is plain HTML, CSS and JavaScript with no build step, no dependencies and no backend. All encryption happens in the browser using the Web Crypto API, and logins are stored encrypted on the device.

## Files

```text
v2/
├── index.html            # the whole app: interface, logic, encryption
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
- Both derived keys use **PBKDF2-HMAC-SHA256** with **600,000 rounds** and a random 16-byte salt per wrap.
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

- Stash locks after 5 minutes of inactivity, and on demand with the lock button.
- When locked, the decrypted logins and keys are cleared from memory.

### Clipboard and screen

- Copied passwords and recovery codes are wiped from the clipboard after 30 seconds, and when Stash locks. Browsers only allow this while Stash is open, so if you switch away first, the wipe happens as soon as you come back.
- A revealed password hides itself again after 20 seconds.

### Upgrades from earlier v2 data

Data saved by early v2 builds (310,000 PBKDF2 rounds) still opens. On the next unlock the master-password key is re-wrapped at 600,000 rounds automatically, and the recovery-code key is re-wrapped the next time the recovery code is used. Existing master passwords shorter than 12 characters still unlock, and Stash shows a reminder to change them.

### Limitations

Stash is a personal project and has not been independently audited. Anyone who controls the server's copy of these files controls the app code the phone loads, so keep the server secure. For the most sensitive accounts, use two-factor authentication as well.
