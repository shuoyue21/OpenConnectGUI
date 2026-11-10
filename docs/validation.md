# Repair architecture and validation

## Lifecycle

`VPNConnectionState` is isolated to the main actor and tracks three separate dimensions:
process lifecycle, underlying network availability, and tunnel recovery state, deriving one
published `Phase`. A connection attempt retains an immutable `activeConfiguration` snapshot,
UUID, execution stage, and line buffer, while `config` holds the configuration for the next
connection (`hasPendingConfigurationChanges` indicates when identity fields differ).

`ManagedProcess` coordinates a 4-stage teardown: graceful `SIGTERM` to allow `vpnc-script`
disconnect, waiting up to `gracefulTimeout` (5s default) for both the main process and its
session-scoped script leases, escalating to `SIGKILL` for verified owned processes/process
groups, and draining output pipes with non-blocking `DispatchSourceRead` bounded by
`logDrainTimeout` (1s default) so leaked pipe descriptors cannot block exit reporting.
Termination delivers a structured `VPNExitOutcome` (`status`, `processConfirmedStopped`,
`wasForceKilled`, `logsComplete`, `networkCleanupComplete`). Sessions are discarded only
when `processConfirmedStopped` is true; forced termination or incomplete cleanup surfaces
a visible failure state. App termination waits up to 12s before cancelling termination and
keeping connection controls active if teardown is still in progress.

Credentials use versioned `credentialID` references bound to `(profileID, server, username,
protocolType)`. Saving a new password writes a new Keychain entry first, atomically persists
the profile file referencing the new `credentialID`, publishes the updated profile, and then
retires the previous Keychain entry (rolling back the new entry on file write failure).
Startup cleans up unreferenced v2 credentials only when profile loading succeeds. Turning
off `rememberCredentials` commits the cleared reference first and schedules retry if Keychain
deletion fails. Deleting an active profile retains the entry until disconnect is confirmed.

Authentication and runtime exits pass through `VPNFailureClassifier`, distinguishing
credential rejection, account lockout, certificate errors, confirmed transient network
errors, user cancellation, local service/cleanup errors, and unclassified failures.
Generic summary lines (`Failed to complete authentication`, `Failed to obtain WebVPN cookie`)
never imply credential rejection on their own. Password updates unblock credential rejection
but never bypass account lockout. Network restoration during an active session enters
`recoveringConnection` with a 15s confirmation window before restoring green connected status.

## Privileged boundary

- `SMAppService` uses the bundled LaunchDaemon plist and helper target.
- The installed tree and all ancestors must be root-owned and not group/world
  writable. Symlinks and ACL grants are rejected. Installation is restricted to
  the fixed protected application path, not an arbitrary user-selected location.
- The application must have a valid Developer ID signature. XPC validates the
  designated code requirement on both ends, rather than checking a mutable PID.
- The helper accepts a bounded JSON tunnel request and a UUID. There is no RPC
  accepting command strings, arbitrary executable/script paths, or a PID.
- The helper supplies fixed protocol/argument/script policy, a clean environment
  and a quoted protected script path. Cookie bytes use stdin, never argv/logs.
- Authentication uses the packaged CA bundle with normal certificate validation;
  the tunnel uses the returned certificate fingerprint and disables system trust
  loading. PKCS#11/user config and external script hook use are not exposed.
- The packager copies the dylib dependency closure, rewrites load paths, signs all
  binaries with the same identity, and leaves hardened runtime/library validation
  enabled in an installable build. The runtime-only smoke-test mode is unprivileged
  and produces no installer; its staging app cannot start the privileged service.

## Automated checks

Run `swift test --scratch-path /tmp/OpenConnectGUI-tests`. Coverage includes:

- Duplicate connect prevention and cancellation during authorization.
- Disconnect acknowledgement and late callbacks from an old session.
- Credential failures followed by network loss/recovery.
- Generic network failures versus explicit credential failures.
- Password/server changes and disabling queued automatic reconnect.
- Split keywords, split UTF-8 and unterminated final log lines.
- Stable connection identity and deletion while a connection stops.
- Remember-off behavior, credential update propagation and Keychain write errors.
- Safe parsing of authentication output without evaluating shell expressions.
- Request/option injection rejection, cookie handling and fixed script arguments.
- Exact legacy sudoers matching and rejection of user-owned runtime files.
- Real unprivileged child-process output streaming/draining, cancellation before
  launch, termination after launch, and safe handling of an early-closed stdin.
- Correct shell quoting of the fixed network script path, including spaces and apostrophes.

Build with the Xcode command in README to validate the GUI and helper targets.

## macOS 27.2 integration checklist (requires signed installed build)

1. Package with Developer ID identities, notarize/staple as appropriate, install,
   then open the protected app. Verify that a missing/refused background approval
   produces an actionable error without an automatic authorization retry loop.
2. Approve the service in System Settings. Verify successful password login,
   routes, DNS and actual VPN traffic against a test gateway.
3. Cancel during authorization, authentication and tunnel startup; verify no
   orphan root OpenConnect child remains. Delete a connecting profile and quit
   the app during connection/connection teardown as additional cases.
4. Disconnect/reconnect rapidly. Delay the old process's exit and verify the new
   connection still has correct status, logs and control.
5. Change network availability and confirm reconnect. A rejected password must
   stop retries until explicit credential update or manual retry.
6. Edit remembered credentials and confirm the next authentication uses them.
   Confirm unremembered credentials never create a profile Keychain item.
7. A differently signed XPC client must be rejected, and a stop request on one
   client's connection must not affect another client's child. Test this against
   disposable sessions; do not signal unrelated processes.
8. Test upgrade from an exact legacy sudoers rule and from a customized rule;
   only the former may be removed. Keep a backup for this integration test.
9. During an application upgrade, stop VPN sessions and unregister the old
   SMAppService before replacing the signed app/helper/plist, then register the
   updated service. This avoids launchd keeping an outdated helper loaded.

Build/unit/runtime-smoke success is not evidence that these system/VPN integration
checks have passed. They require an installed signed application and a gateway.

## Checks performed in this repair (2026-11-07)

- Xcode Debug application and helper build: passed.
- Xcode `build-for-testing`, including unit/UI test compilation: passed.
- Swift package lifecycle/protocol/process tests: 24 regression tests; see the final
  test output for the current run. These tests use mocked Keychain/XPC boundaries
  and real unprivileged child processes; they do not launch the privileged service.
- Runtime packaging smoke test: dependency copying/load-path rewriting/signature
  integrity check and the bundled OpenConnect 9.21 `--version` invocation passed.
- The current signing-identity check found zero valid identities. An ad-hoc
  hardened OpenConnect failed macOS library validation, so installable packages
  require Developer ID signing; runtime-only verification remains unprivileged.
- No signed installer was deployed, no system sudoers file was modified, and no
  real gateway/network routing test was performed. Background approval, XPC peer
  rejection, legacy-rule migration and tunnel teardown remain integration checks.
