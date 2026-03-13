# DeskAuth — Secure 2FA Authenticator for your Desktop

> A lightweight Chrome Extension that brings your 2FA codes to your desktop — fast, offline, and encrypted.
> Published by **[Harakawa Tech](http://deskauth.harakawa.tech/)**

---

## What is DeskAuth?

DeskAuth is a Chrome Extension that generates **TOTP (Time-based One-Time Password)** codes — the
same 6-digit codes used by Google Authenticator, Authy, and similar apps — directly inside your
browser.

Key design principles:

- **100 % offline** — no external APIs, no analytics, no network requests.
- **Local encryption** — secrets are encrypted with AES-256-GCM before being stored in
  `chrome.storage.local`. Plaintext secrets never touch disk.
- **No external dependencies** — every feature is implemented using browser-native APIs
  (Web Crypto, `chrome.storage`, ES modules).
- **Manifest V3** — built on the latest Chrome Extension platform for better security and
  performance.

---

## Loading the extension locally (Development)

1. **Clone or download** this repository to your machine.

2. Open Chrome and navigate to:
   ```
   chrome://extensions
   ```

3. Enable **Developer mode** (toggle in the top-right corner).

4. Click **"Load unpacked"**.

5. Select the `DeskAuth - 2FA Authenticator` folder (the one containing `manifest.json`).

6. The DeskAuth icon will appear in your Chrome toolbar. Click it to open the popup.

> **Tip:** After editing any source file, go back to `chrome://extensions` and click the
> refresh icon on the DeskAuth card to reload the extension.

---

## Project file structure

```
DeskAuth - 2FA Authenticator/
│
├── manifest.json        Chrome Extension Manifest V3 — permissions, icons, entry point
│
├── popup.html           Main popup UI — rendered when the toolbar icon is clicked
├── popup.css            Styles for the popup (dark theme, account cards, modal, toast)
├── popup.js             UI controller — renders accounts, handles events, delegates to modules
│
├── totp.js              TOTP / HOTP generator (RFC 6238 / RFC 4226) — Web Crypto API
├── storage.js           Account CRUD via chrome.storage.local (encrypts secrets via crypto.js)
├── crypto.js            AES-256-GCM encryption / decryption using Web Crypto API
├── qr-import.js         Parses otpauth:// URIs; will decode QR codes from images
├── utils.js             Shared helpers: ID generation, clipboard, toast, base32 validation
│
├── icons/
│   ├── icon16.png       Toolbar icon (16 × 16)
│   ├── icon32.png       Toolbar icon (32 × 32)
│   ├── icon48.png       Extension management page icon (48 × 48)
│   └── icon128.png      Chrome Web Store icon (128 × 128)
│
└── README.md            This file
```

---

## Implementation status

| Module | Status | Notes |
|---|---|---|
| `popup.html` / `popup.css` | ✅ Done | Full UI scaffold with account cards, modal, empty state |
| `popup.js` | ✅ Done | UI wired up; delegates to modules below |
| `utils.js` | ✅ Done | ID gen, clipboard, toast, base32 helpers, encoding utils |
| `storage.js` | 🚧 Scaffold | CRUD works; encryption passthrough until `crypto.js` is complete |
| `totp.js` | 🚧 Scaffold | Returns `------` stub; full RFC 6238 implementation pending |
| `crypto.js` | 🚧 Scaffold | AES-GCM structure defined; key derivation & encryption pending |
| `qr-import.js` | 🚧 Scaffold | URI parser & QR decode pending; jsQR integration planned |

---

## Roadmap

### Phase 1 — TOTP engine (`totp.js`)
- [ ] Implement `decodeBase32()` — RFC 4648 alphabet decoder
- [ ] Implement `counterToBytes()` — 64-bit big-endian encoding
- [ ] Implement `importHmacKey()` — HMAC-SHA1 key import via Web Crypto
- [ ] Implement `truncate()` — RFC 4226 dynamic truncation
- [ ] Wire up `generateTOTP()` end-to-end

### Phase 2 — Encryption (`crypto.js`)
- [ ] Implement `toBase64()` / `fromBase64()`
- [ ] Implement `getOrCreateKey()` — PBKDF2 key derivation with persisted salt
- [ ] Implement `encryptSecret()` — AES-256-GCM encrypt
- [ ] Implement `decryptSecret()` — AES-256-GCM decrypt
- [ ] Update `storage.js` to call encrypt/decrypt (remove plaintext passthrough)

### Phase 3 — QR import (`qr-import.js`)
- [ ] Bundle jsQR (MIT) as `vendor/jsqr.js`
- [ ] Implement `fileToImageData()` — file → canvas → ImageData
- [ ] Implement `decodeQRFromImage()` — jsQR wrapper
- [ ] Implement `parseOtpAuthURI()` — full otpauth:// parser
- [ ] Wire up "Import QR" button flow in `popup.js`

### Phase 4 — Polish
- [ ] Account reordering (drag & drop)
- [ ] Account editing (update issuer / name)
- [ ] Export / backup (encrypted JSON)
- [ ] Optional master password prompt
- [ ] Keyboard navigation & accessibility audit

---

## Security notes

- Secrets are stored in `chrome.storage.local`, which is scoped to this extension only.
- Once `crypto.js` is complete, all secrets will be AES-256-GCM encrypted at rest.
- No data ever leaves the browser. There are no remote endpoints, no telemetry.
- The Content Security Policy in `manifest.json` blocks all inline scripts and external sources.

---

## Author

DeskAuth was created by **Weslley Harakawa**, software engineer and founder of **Harakawa Tech**.

| | |
|---|---|
| 🌐 Website | [deskauth.harakawa.tech](http://deskauth.harakawa.tech/) |
| 💼 LinkedIn | [linkedin.com/in/weslleyharakawa](https://www.linkedin.com/in/weslleyharakawa/) |
| 🐙 GitHub | [github.com/weslleyharakawa](https://github.com/weslleyharakawa/) |

---

## Support the Project

DeskAuth is a free and open-source project.
If you find it useful, you can support its development here:

☕ **[Buy Me a Coffee](https://buymeacoffee.com/weslleyaharakawa)**

Your support helps keep the project maintained and evolving. Thank you!

---

## License

MIT License © 2026 Harakawa Tech
