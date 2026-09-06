# Iffy‑Checker (Chrome Extension)

**Iffy‑Checker** is a Google Chrome (Manifest V3) extension that automatically checks visited online stores against the official **CERT‑HR Iffy** database ([iffy.cert.hr](https://iffy.cert.hr/)) to protect users against fraudulent web shops and phishing scams.

---

## Features

- **Automatic Background Protection**: Automatically verifies store domains during browsing and displays status badges directly on the extension toolbar icon:
  - `OK` (Green): Verified safe / not in the database of fraudulent stores.
  - `WRN` (Red): Identified as a suspicious or fraudulent web shop.
  - `WHT` (Blue): Domain is on your trusted whitelist.
  - `ERR` (Gray): Network or verification error.
- **Detailed Popup Dashboard**:
  - Immediate visual shield card indicating domain safety.
  - One-click "Trust this domain" whitelist toggle.
  - Manual domain search form for testing any URL or store address.
- **Activity History**: Tracks recent checks with timestamps and quick-delete controls.
- **Whitelist Manager**: Add, remove, and manage trusted domains with automatic `www.` normalization.
- **Privacy First**: Only sanitized domain names (e.g. `trgovina.hr`) are transmitted to the verification API. Full URLs, paths, query parameters, search queries, and personal data are never sent or stored.
- **Fast & Efficient**: Built-in in-memory caching and session reuse minimize network requests and optimize performance.

---

## Installation (Developer Mode)

Since this is a custom extension, install it directly in Chromium browsers:

1. Clone or download this repository to your local computer.
2. Open Google Chrome (or Edge, Brave, etc.) and navigate to:
   ```text
   chrome://extensions
   ```
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select this project folder (`iffy-checker`).
6. The Iffy‑Checker icon will appear in your extension toolbar! Pin it for easy viewing.

---

## Project Structure

```text
├── manifest.json         # Extension Manifest V3 configuration
├── service_worker.js     # Background worker (caching, API calls, badges)
├── popup/
│   ├── popup.html        # Extension popup UI (Tabs: Safety, History, Settings)
│   ├── popup.css         # Google Material 3 styling (light & dark mode support)
│   ├── popup.js          # Interactive popup logic & DOM management
│   └── about.html        # Options & Privacy documentation page
├── icons/
│   ├── icon16.png        # 16x16 icon
│   ├── icon48.png        # 48x48 icon
│   └── icon128.png       # 128x128 icon
└── README.md
```

---

## Disclaimer

This is an unofficial open-source project and is not affiliated with CARNET or National CERT. Verification results are provided for informational purposes relying on the public CERT iffy service.
