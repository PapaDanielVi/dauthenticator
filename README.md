# DAuthenticator

A local, privacy-first TOTP and HOTP two-factor authenticator for Google Chrome (Manifest V3), written in TypeScript.

It encrypts everything at rest with AES-256-GCM, stores the vault strictly in `chrome.storage.local`, caches session keys in memory only, handles one-time code autofill for single and split input boxes, and imports exports from major authenticator apps.

Author: Danny ([github.com/PapaDanielVi](https://github.com/PapaDanielVi))

---

## Security Architecture

1. Zero-knowledge local vault: All secret seeds are encrypted at rest using Web Crypto (`crypto.subtle`). Key derivation uses PBKDF2 with SHA-256, 600,000 iterations, and a random 16-byte salt per vault. Encryption uses AES-256-GCM with a fresh 12-byte IV drawn for every write. Plaintext secrets never touch persistent storage or disk.
2. Isolated storage: The encrypted vault lives strictly in `chrome.storage.local`. It never touches `window.localStorage`, `sessionStorage`, or `IndexedDB`, so clearing browser history or cache will not wipe your accounts. During service worker startup and initialization, `chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })` blocks untrusted page contexts and content scripts from reading the vault directly.
3. In-memory session key: Unlocking the vault places the derived 256-bit AES key into `chrome.storage.session`. This storage area lives strictly in memory. When the browser closes, the key is gone, so you do not need to retype your master password on every popup click while your session is active.
4. Auto-lock protection: The extension monitors user inactivity and system lock events. If you step away for a configurable period (default 15 minutes) or lock your machine, the in-memory session key is purged immediately.

---

## Core Capabilities

### Code Generation Engine
- RFC 6238 (TOTP) and RFC 4226 (HOTP) implementation built on native Web Crypto HMAC.
- Hash algorithms: SHA-1, SHA-256, and SHA-512.
- Digits: 6 digits and 8 digits.
- Periods: 30 seconds (default), 60 seconds, or custom intervals (1 to 86,400 seconds).
- Real-time circular countdown progress rings synchronized to the Unix epoch clock.
- Manual HOTP counter progression with immediate persistent state updates.

### Adding New Accounts
- Visible Screen QR Capture: Uses `chrome.tabs.captureVisibleTab` and `jsQR` to scan the active browser tab for QR codes.
- Direct Image Upload: Drop a screenshot or photo of a QR code anywhere on the popup or options page, or use the file picker button.
- Webcam / Camera Scanner: Point your laptop or desktop camera at a phone screen or physical card. Automatically detects and parses the code.
- Multi-Part Batch QR Support: Google Authenticator splits large exports into batches (for example, "1 of 3"). The camera scanner detects batch indices, prompts you to scan each part, and merges all accounts once complete.
- Multi-QR Image Extraction: If an image or screen has multiple QR codes side by side, iterative canvas masking detects and imports all of them in a single pass.
- Manual Entry: Dedicated form for Issuer, Account Label, Base32 Secret, Algorithm, Digits, Period, Counter, and Domain association.

### DOM Autofill Content Script
- Triggered via keyboard shortcut (`Command+Shift+L` on macOS, `Ctrl+Shift+L` on Windows and Linux) or by clicking the Fill button in the popup.
- Matches current tab hostname against account issuers and custom domain lists.
- Detects inputs via standard attributes (`autocomplete="one-time-code"`) and semantic heuristics (`otp`, `totp`, `2fa`, `mfa`, `verification`, `security-code`).
- Supports split 6-box input fields where each single digit is housed in a separate input box, even when wrapped in nested layout divs.
- Sets values through prototype property descriptors and dispatches native `input`, `change`, `keydown`, and `keyup` events so form state updates properly in React, Vue, Angular, and Svelte applications.

### Multi-Authenticator Import Engine
Accepts exports from popular authenticators and normalizes them into unified account records:

| Provider / Format | File / Input Type | Details |
|---|---|---|
| Google Authenticator | `otpauth-migration://` | Zero-dependency binary Protobuf reader decodes `MigrationPayload` and `OtpParameters` from text, screen, image, or webcam. Handles single and multi-batch exports. |
| 2FAS Authenticator | `.2fas`, `.json` | Parses `services` array. Decrypts password-protected `servicesEncrypted` payloads via PBKDF2 and AES-256-GCM. |
| Aegis Authenticator | `.json` | Parses plain exports and decrypts password-protected exports using scrypt and AES-256-GCM master key unwrapping. |
| Bitwarden | `.json`, `.csv` | Extracts TOTP seeds and URIs from vault exports and Bitwarden Authenticator backups. Automatically assigns login URIs as matching domains. |
| Standard URI Lists | `.txt`, `.uri` | Reads files with newline or comma-separated `otpauth://totp/...` and `otpauth://hotp/...` links (Ente Auth, Raivo, plain text). |
| Generic JSON / CSV | `.json`, `.csv` | Heuristic key inspector recognizes field names like `secret`, `totp`, `seed`, `issuer`, `account`, and `label`. |
| Raw Base32 QR Codes | Image / Text | Fallback mapper for services whose QR codes encode only the raw secret string. |

### Backups and Failsafe Sync
- One-Click Encrypted Backup: Export a `.enc` or encrypted `.json` file at any time. Because it is already protected by your master password, you do not need to retype credentials to save a copy.
- Decrypted Export: Export plaintext JSON or `otpauth://` lists after confirming your master password.
- Chrome Storage Sync: Mirrors your encrypted vault to `chrome.storage.sync` as a failsafe against accidental extension removal. Large vaults are split into chunks under 8 KB with SHA-256 integrity verification. Restoring from sync is non-destructive and merges remote accounts without deleting local ones.

---

## Project Structure

```
dauthenticator/
├── public/
│   ├── manifest.json            # Manifest V3 configuration with least privilege
│   └── icons/                   # Extension icons (16, 32, 48, 128 px)
├── src/
│   ├── background/
│   │   └── serviceWorker.ts     # Storage hardening, auto-lock alarm, shortcut command
│   ├── content/
│   │   └── autofill.ts          # DOM inspection, split input handling, event dispatch
│   ├── crypto/
│   │   ├── encoding.ts          # Base64, hex, utf8, memory wipe helpers
│   │   ├── totp.ts              # RFC 6238 / RFC 4226 Web Crypto generator and Base32 codec
│   │   └── vault.ts             # PBKDF2 key derivation, AES-GCM encryption, session cache
│   ├── importers/
│   │   ├── csv.ts               # RFC 4180 CSV parser with delimiter detection
│   │   ├── encryptedBackups.ts  # Aegis (scrypt) and 2FAS decryption
│   │   ├── fileImporters.ts     # Unified import dispatcher
│   │   ├── googleMigration.ts   # Minimal zero-dependency Protobuf wire reader
│   │   ├── heuristic.ts         # Generic JSON / CSV key inspector
│   │   ├── otpauthUri.ts        # RFC compliant otpauth URI parser and serializer
│   │   ├── qr.ts                # Screen capture and multi-pass QR image decoder
│   │   └── qrScanner.ts         # Live webcam viewfinder scanner
│   ├── options/
│   │   ├── options.html         # Settings, multi-app imports, backup, sync
│   │   ├── options.css          # Options page stylesheet
│   │   └── options.ts           # Options page controller
│   ├── popup/
│   │   ├── popup.html           # Main extension UI and modal forms
│   │   ├── popup.css            # Dark mode UI styles, timer rings, viewfinder
│   │   └── popup.ts             # Vault view state, search, countdown loop, autofill
│   └── shared/
│       ├── accounts.ts          # Validation, normalization, merging, sorting
│       ├── export.ts            # Encrypted and plaintext file downloads
│       ├── match.ts             # Domain normalization and autofill scoring
│       ├── settings.ts          # User preferences persistence
│       ├── sync.ts              # Chunked chrome.storage.sync implementation
│       └── types.ts             # Shared TypeScript interfaces
├── tests/
│   ├── crypto/                  # Cryptography and RFC test vectors
│   ├── importers/               # Protobuf, Aegis, 2FAS, Bitwarden, and CSV tests
│   ├── setup/                   # Chrome extension mock environment for Vitest
│   └── shared/                  # Matcher, sync chunking, and export tests
├── package.json
├── tsconfig.json
├── vite.config.ts
├── vite.content.config.ts
└── vitest.config.ts
```

---

## Build and Installation

### Prerequisites
- Node.js 20 or newer
- npm

### Installation Commands

```bash
# Install dependencies
npm install

# Run the test suite (38 unit tests verifying RFC vectors and importers)
npm test

# Typecheck TypeScript files
npm run typecheck

# Build extension into dist/
npm run build

# Or use Make to run tests, build, and package in one step
make package
```

### Loading the Extension into Google Chrome

1. Build the extension with `npm run build` or `make build`.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable "Developer mode" via the toggle in the top right corner.
4. Click "Load unpacked" in the top left.
5. Select the `dist/` directory inside this repository.
6. Open the extension popup from your browser toolbar, set your master password, and start adding accounts.

---

## Permissions Breakdown

The extension requests only permissions necessary for its functionality:

| Permission | Reason |
|---|---|
| `storage` | Required to store the encrypted vault and user preferences in `chrome.storage.local`. |
| `unlimitedStorage` | Exempts the encrypted vault from standard browser quota evictions. |
| `activeTab` | Grants temporary access to take a screen capture when you click "Scan screen for QR code". |
| `scripting` | Injects the autofill content script on demand into the active page when triggered. |
| `alarms` | Runs periodic inactivity checks for the auto-lock feature. |
| `idle` | Detects when the operating system locks the screen so the vault can lock immediately. |

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
