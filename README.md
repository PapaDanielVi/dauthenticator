# DAuthenticator

A local, privacy-first TOTP and HOTP two-factor authenticator for Google Chrome (Manifest V3), written in TypeScript.

It encrypts everything at rest with AES-256-GCM, stores the vault strictly in `chrome.storage.local`, caches session keys in memory only, handles one-time code autofill for single and split input boxes, and imports exports from major authenticator apps.

Author: Danny ([github.com/PapaDanielVi](https://github.com/PapaDanielVi))

---

## Security Model

1. Zero-knowledge local vault: All secret seeds are encrypted at rest using Web Crypto (`crypto.subtle`). Key derivation uses PBKDF2 with SHA-256, 600,000 iterations, and a random 16-byte salt per vault. Encryption uses AES-256-GCM with a fresh 12-byte IV drawn for every write.
2. Isolated storage: The encrypted vault lives strictly in `chrome.storage.local`. It never touches `localStorage`, `sessionStorage`, or `IndexedDB`, so clearing browser history or cache will not wipe your accounts. During service worker startup, `chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })` blocks untrusted page contexts and content scripts from reading the vault directly.
3. In-memory session key: Unlocking the vault places the derived key into `chrome.storage.session`. This area lives only in memory. When the browser closes, the key is gone, so you do not need to retype your master password on every popup click while your session is active.
4. Auto-lock protection: The extension monitors user inactivity and system lock events. If you step away or lock your machine, the in-memory session key is purged immediately.

---

## What It Does

- Code generation: Full RFC 6238 (TOTP) and RFC 4226 (HOTP) generator running on Web Crypto HMAC. Supports SHA-1, SHA-256, and SHA-512 algorithms, 6 and 8 digits, and custom periods (30s, 60s, or arbitrary steps).
- Search and pin: Filter accounts instantly through the search bar. Pin accounts to keep them at the top with a distinct background highlight.
- DOM autofill: Press `Command+Shift+L` (Mac) or `Ctrl+Shift+L` (Windows and Linux) or click the Fill button in the popup. The content script matches the page hostname against account domains and issuers, finds the input (`autocomplete="one-time-code"` or matching heuristics), and dispatches native input and change events. It handles both standard single inputs and split 6-box input fields.
- Universal imports:
  - Google Authenticator: decodes `otpauth-migration://` links from single or batch export QR codes using a zero-dependency Protocol Buffers wire reader.
  - 2FAS: reads `.2fas` and `.json` files, including password-protected exports.
  - Aegis: reads `.json` exports, including password-encrypted vaults using scrypt and AES-GCM.
  - Bitwarden: imports logins with TOTP seeds from Bitwarden JSON and CSV files.
  - Standard lists: accepts files with newline or comma-separated `otpauth://` links (Ente, Raivo, plaintext).
  - Generic JSON and CSV: fallback mapper looks for keys like `secret`, `totp`, `issuer`, `account`, and `seed`.
- Backups and sync:
  - Export a `.dauth.enc` file anytime. Because it is already encrypted with your master password, you do not have to re-enter credentials to back it up.
  - Export plaintext JSON or `otpauth://` lists by confirming your master password.
  - Mirror your encrypted vault to `chrome.storage.sync` in chunks under 8 KB with SHA-256 integrity verification.

---

## Build and Test

Requirements: Node.js 20 or newer, and npm.

### Quick Start with Make

```bash
# View available commands
make help

# Install dependencies, run tests, and compile the extension
make test
make build

# Package into a zip archive ready for distribution
make package
```

### Manual npm Scripts

```bash
# Install dependencies
npm install

# Run Vitest test suite (36 unit and integration tests)
npm test

# Typecheck TypeScript files
npm run typecheck

# Build the extension into dist/
npm run build
```

---

## Loading into Google Chrome

1. Run `make build` (or `npm run build`) to produce the `dist/` directory.
2. Open Google Chrome and go to `chrome://extensions/`.
3. Switch on the "Developer mode" toggle in the top right corner.
4. Click "Load unpacked" on the top left.
5. Select the `dist/` folder inside this repository.
6. Click the extension icon in the toolbar, set your master password, and start adding accounts.

To distribute or share the extension, run `make package` to generate `dauthenticator.zip`. This file contains the complete Manifest V3 package ready for upload to the Chrome Web Store Developer Dashboard or for manual distribution.
