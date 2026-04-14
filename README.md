# ⚡ BleskWallet

A lightweight self-hosted Lightning Network wallet as a PWA (Progressive Web App). No app to download — runs directly in the browser or can be installed to the home screen like a native app.

Uses [LNBits](https://lnbits.com/) as the Lightning backend.

---

> **⚠️ Warning: Work in Progress — Use at your own risk**
>
> This is a hobby project in active development. It has **not been professionally tested, audited, or reviewed** for security vulnerabilities. Do **not** use it to store large amounts of sats. The software is provided as-is, without any warranty. Always keep your seed phrase backed up safely — losing it means losing access to your funds permanently.

---

## Features

- **Send & receive sats** via Lightning Network (BOLT11 invoices)
- **QR scanner** — scan invoices, LNURLs, or Lightning addresses directly from the camera
- **Animated BC-UR QR codes** — multi-frame QR support for large payloads
- **LNURL-pay** — pay via LNURL or Lightning address (`user@domain.com`)
- **LNURL-withdraw** — receive sats via LNURL-w (e.g. faucets)
- **Cashu tokens** — redeem ecash tokens back to Lightning
- **Lightning address** — every user gets their own address (`gw_xxx@yourdomain.com`)
- **Push notifications** — get notified on incoming payments even when the app is closed
- **Encrypted seed storage** — seed phrase encrypted with AES-GCM directly in the browser
- **Transaction history** with full payment detail view
- **PWA** — installable on iOS and Android

---

## How it works

```
Browser (PWA)
    │
    │  REST API
    ▼
BleskWallet server (Node.js / Express)
    │
    │  LNBits API
    ▼
LNBits instance (Lightning backend)
    │
    ▼
Lightning Network
```

The seed phrase never leaves the browser. A username and password are derived deterministically from the seed and used to authenticate with LNBits. The server returns wallet keys (inkey, adminkey) which are kept only in browser memory for the duration of the session.

---

## Requirements

- **Node.js** 18+ (20+ recommended)
- A **LNBits** instance (self-hosted or public, e.g. [lnbits.com](https://lnbits.com))
- For push notifications and Lightning addresses: server accessible over **HTTPS** with a real domain

---

## Installation

```bash
git clone https://github.com/your-username/bleskwallet.git
cd bleskwallet
npm install
```

---

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

```env
PORT=3232
LNBITS_URL=https://your-lnbits-instance.com

# Web Push notifications — generate VAPID keys (see below)
VAPID_EMAIL=mailto:admin@your-domain.com
VAPID_PUBLIC_KEY=
VAPID_PRIVATE_KEY=
```

### Generating VAPID keys (push notifications)

```bash
node -e "import('web-push').then(m => { const k = m.default.generateVAPIDKeys(); console.log('VAPID_PUBLIC_KEY=' + k.publicKey); console.log('VAPID_PRIVATE_KEY=' + k.privateKey); })"
```

---

## Running

```bash
node server.js
```

The app will be available at `http://localhost:3232`.

---

## Running as a systemd service

Create `/etc/systemd/system/bleskwallet.service`:

```ini
[Unit]
Description=BleskWallet Node.js Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/bleskwallet
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bleskwallet
```

View logs: `journalctl -u bleskwallet -f`

---

## Nginx reverse proxy (recommended)

```nginx
server {
    listen 443 ssl;
    server_name wallet.your-domain.com;

    # SSL certificate (e.g. Let's Encrypt)
    ssl_certificate     /etc/letsencrypt/live/wallet.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wallet.your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3232;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Push notifications

Once VAPID keys and an HTTPS domain are configured:

1. Open the app → Settings → **Notifications: off** → tap to enable
2. The browser will ask for notification permission
3. You'll receive alerts for incoming payments even when the app is closed

Subscriptions are stored in `push-subscriptions.json` (excluded from git automatically).

---

## Lightning address

Every user automatically gets a Lightning address in the format `gw_xxxxxxxxxxxxxxxx@your-domain.com`.

**Requirements:**
- The app must be running on a publicly accessible HTTPS domain
- The domain must match what the user sees in the browser

The address is shown on the main wallet screen after logging in.

---

## Security

- The seed phrase **never leaves the browser** — the server never sees it
- The seed is stored in `localStorage` encrypted with AES-GCM (key derived via PBKDF2 from the seed itself)
- During a session the seed is held in `sessionStorage` in plaintext (cleared when the tab is closed)
- Rate limiting on all API endpoints (`/api/*`): 200 requests / 15 minutes
- HTTP headers hardened with [Helmet](https://helmetjs.github.io/)
- SSRF protection — the server blocks requests to internal/private network addresses

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Backend | Node.js, Express, web-push |
| Frontend | Vanilla JS, PWA, WebCrypto API |
| Lightning | LNBits REST API |
| QR scanning | html5-qrcode |
| BC-UR | @ngraveio/bc-ur |
| Ecash | @cashu/cashu-ts |
| HD wallet | ethers.js (BIP39 mnemonic) |

---

## License

MIT
