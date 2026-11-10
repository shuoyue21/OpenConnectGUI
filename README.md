# OpenConnectGUI

![Platform](https://img.shields.io/badge/platform-macOS%2015.4%2B-blue)
![Swift](https://img.shields.io/badge/Swift-5%20%2F%206-orange)
![License](https://img.shields.io/badge/license-MIT-green)

**OpenConnectGUI** is a lightweight, native macOS client for [OpenConnect](https://www.infradead.org/openconnect/), built with SwiftUI.

If you need to connect to a corporate or university VPN (Cisco AnyConnect, GlobalProtect, Pulse Secure, Fortinet, etc.) on macOS without installing heavy vendor clients—or keeping a `sudo openconnect` terminal tab open all day—this app gives you a clean GUI and menu bar workflow.

---

## What It Does

- **Out-of-the-box OpenConnect runtime** — Bundles `openconnect` (9.21), `vpnc-script`, and required libraries inside the app, so you don't need to manually wire up Homebrew paths just to get connected.
- **One-time privilege setup** — Tunnel creation on macOS requires root privileges. On your first connection, the app asks for administrator authorization once to install a dedicated helper under `/Library/Application Support/OpenConnectGUI/runtime`. Subsequent connections and reconnects work without `sudo` password prompts.
- **Menu bar integration** — Closing the main window (`⌘W` or the red close button) tucks the app into the macOS menu bar so you can check tunnel status, switch profiles, or disconnect with two clicks.
- **Multi-protocol & Auth Group support** — Supports Cisco AnyConnect (`anyconnect`), Palo Alto GlobalProtect (`gp`), Pulse Secure (`pulse`), Juniper Network Connect (`nc`), F5 BIG-IP (`f5`), Fortinet FortiGate (`fortinet`), and Array Networks (`array`). If your gateway requires a login group (`--authgroup`) and you haven't set one yet, the app detects the available groups and prompts you to choose.
- **Smart auto-reconnect** — Automatically recovers the tunnel after macOS sleep/wake or temporary Wi-Fi drops, while stopping retries immediately if credentials are rejected or the account is locked.
- **System CA integration** — Automatically merges trusted root certificates from macOS `System.keychain` with the bundled CA store, so internal enterprise or campus CAs work without disabling certificate verification.
- **Local encrypted credentials** — Optional "Remember Credentials" stores passwords locally using AES-GCM encryption bound to your profile and machine identity, avoiding repeated Keychain access popups across rebuilds.

---

## Getting Started

### Requirements

- **macOS 15.4** or later
- **Xcode 16+** (to build from source)

### Build and Run in Xcode

```bash
git clone git@github.com:shuoyue21/OpenConnectGUI.git
cd OpenConnectGUI
open OpenconnectGUI.xcodeproj
```

Select the **OpenconnectGUI** scheme in Xcode and press **⌘R** to build and run.

### Build from Command Line

```bash
xcodebuild -project OpenconnectGUI.xcodeproj \
  -scheme OpenconnectGUI \
  -configuration Release \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO build
```

The built application bundle will be located at:

```
build/Build/Products/Release/OpenconnectGUI.app
```

Move `OpenconnectGUI.app` to `/Applications` (or run it directly), add your VPN server and username, and click **Connect**.

---

## Running Tests

Core lifecycle, credential encryption, failure classification, and process supervision logic are covered by a standalone Swift Package test suite:

```bash
swift test
```

---

## Packaging a Standalone Installer (Optional)

If you want to refresh the bundled OpenConnect runtime from a local installation (such as `brew install openconnect`) or build a signed `.pkg` installer for distribution, use [Scripts/package_app.py](Scripts/package_app.py):

```bash
# Verify and re-bundle runtime dependencies without a signing certificate
python3 Scripts/package_app.py \
  --app build/Build/Products/Release/OpenconnectGUI.app \
  --openconnect /opt/homebrew/bin/openconnect \
  --vpnc-script /opt/homebrew/etc/vpnc/vpnc-script \
  --verify-runtime-only \
  --output dist/runtime-check
```

For a signed `.pkg` installer, pass `--sign-identity` (Developer ID Application) and optionally `--installer-identity` (Developer ID Installer). See [docs/validation.md](docs/validation.md) for architecture details.

---

## Limitations

- Currently focused on password-based authentication (`--passwd-on-stdin`). Interactive browser-based SAML/SSO popups and hardware token (PKCS#11) prompts are not supported in the GUI yet.

---

## Credits & License

Originally created by [Mikołaj Jucha (AshenMJ)](https://github.com/mikolajjucha/OpenConnectGUI).

Licensed under the [MIT License](LICENSE). Bundled OpenConnect binaries and third-party libraries under `Support/OpenConnect` retain their respective licenses (see `Support/OpenConnect/licenses/`).
