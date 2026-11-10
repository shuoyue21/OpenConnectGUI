# OpenconnectGUI

A native macOS SwiftUI frontend for OpenConnect, with saved VPN profiles,
Keychain credentials, connection logs and automatic reconnect.

Requires macOS 15.4 or later. The current repair targets the user's macOS 27.2
runtime; the Xcode deployment target remains 15.4.

## Build and test

```sh
swift test --scratch-path /tmp/OpenConnectGUI-tests
xcodebuild -project OpenconnectGUI.xcodeproj -scheme OpenconnectGUI \
  -configuration Debug -derivedDataPath /tmp/OpenConnectGUI-build \
  CODE_SIGNING_ALLOWED=NO build
```

These commands build the app and helper and run isolated regression tests. They
do not install/register a service, change sudoers or connect a real VPN. The
Swift package tests use temporary profile files and in-memory credentials.

## Install a build that can connect

VPN tunnel creation now runs through a restricted `SMAppService` LaunchDaemon.
The app no longer installs broad `NOPASSWD` rules or launches Homebrew binaries
as root. Authentication runs as the user; only the resulting cookie crosses the
XPC boundary to the helper. Both sides verify the other's code signature.

The app, helper, OpenConnect libraries and network script must be installed as
root-owned files under:

```
/Library/Application Support/OpenConnectGUI/OpenconnectGUI.app
```

Use a trusted OpenConnect distribution on the build machine (for example,
`brew install openconnect`) and a **Developer ID Application** signing identity:

```sh
python3 Scripts/package_app.py \
  --app /tmp/OpenConnectGUI-build/Build/Products/Debug/OpenconnectGUI.app \
  --openconnect /opt/homebrew/bin/openconnect \
  --vpnc-script /opt/homebrew/etc/vpnc/vpnc-script \
  --sign-identity 'Developer ID Application: YOUR NAME (TEAMID)' \
  --installer-identity 'Developer ID Installer: YOUR NAME (TEAMID)' \
  --output /tmp/OpenConnectGUI-package
```

Use a new output directory for each invocation. The script copies the recursive
dylib dependency closure, removes external runtime library paths, signs the
runtime/helper/app, verifies signatures and runs `openconnect --version` as the
ordinary build user. Then it creates `OpenconnectGUI.pkg`; it never installs it.
The installer identity is optional for local testing; use it for distribution.

Before distribution, submit the signed package using your configured Apple
notarization workflow and staple the notarization ticket. LaunchDaemons require
properly signed/notarized applications. Keep the included third-party notices
and supply corresponding source/relinking materials as required by the bundled
OpenConnect/dependency licenses.

Install the package, then open the protected application:

```sh
open '/Library/Application Support/OpenConnectGUI/OpenconnectGUI.app'
```

At the first connection, allow its background service in System Settings →
General → Login Items & Extensions, then connect again. The application's
**VPN Background Service Settings…** menu opens that settings page. Keep a Finder
alias in Applications or the Dock if desired; running a separately copied
bundle is intentionally rejected.

Without a signing identity, verify runtime packaging without creating an
installable privileged-service build:

```sh
python3 Scripts/package_app.py \
  --app /tmp/OpenConnectGUI-build/Build/Products/Debug/OpenconnectGUI.app \
  --openconnect /opt/homebrew/bin/openconnect \
  --vpnc-script /opt/homebrew/etc/vpnc/vpnc-script \
  --verify-runtime-only --output /tmp/OpenConnectGUI-runtime-check
```

## Credentials and upgrades

- “Remember Credentials” alone controls Keychain persistence. An unremembered
  password remains in memory only for its connection/reconnect cycle.
- Editing a password updates the next reconnect. Changing server/user/protocol
  invalidates the previous credential cache and pending reconnects.
- Credentials are stored per profile UUID. Existing remembered Internet Password
  entries are imported once; legacy entries are preserved because they can also
  belong to another profile/application. Forgotten entries are not reimported.
- After the signed helper is available, it removes only the exact legacy
  `/etc/sudoers.d/openconnectgui` rule produced by this application for the
  connecting user. Customized rules and other users' rules are preserved with
  a log message. No new sudoers rule is installed.
- Updating an installed helper/plist may require unregistering and registering
  the service again; see [the validation guide](docs/validation.md).

The current UI supports noninteractive username/password authentication. It
does not provide interactive OTP, SAML/browser or certificate-selection flows.
The packaged CA bundle defaults to `/etc/ssl/cert.pem` from the build machine;
use `--ca-bundle` when packaging for an organization with a private CA. Certificate
validation is retained; the root tunnel pins the certificate returned by user
authentication. External vpnc-script hooks are disabled in the packaged runtime.

## License

See [LICENSE](LICENSE). OpenConnect and bundled libraries retain their own licenses.
