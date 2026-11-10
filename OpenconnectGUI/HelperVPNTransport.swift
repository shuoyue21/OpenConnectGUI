import Foundation

@MainActor
final class HelperVPNTransport: NSObject, VPNTransport {
    private final class Attempt {
        let id: UUID
        let config: VPNConfiguration
        let receive: @MainActor (VPNTransportEvent) -> Void
        var cancelled = false
        var auth: ManagedProcess?
        var authOutput = Data()
        var tunnel: ManagedProcess?
        var tunnelOutcomeData = Data()
        var startingTunnel = false
        var setupTask: Task<Void, Never>?
        init(id: UUID, config: VPNConfiguration, receive: @escaping @MainActor (VPNTransportEvent) -> Void) {
            self.id = id
            self.config = config
            self.receive = receive
        }
    }

    private var attempt: Attempt?

    func start(
        session: UUID,
        config: VPNConfiguration,
        password: String,
        receive: @escaping @MainActor (VPNTransportEvent) -> Void
    ) {
        guard attempt == nil else {
            receive(.failed("A VPN operation is still running."))
            return
        }
        let work = Attempt(id: session, config: config, receive: receive)
        attempt = work
        work.setupTask = Task { [weak self, weak work] in
            guard let self, let work else { return }
            do {
                try await Task.detached(priority: .userInitiated) {
                    try Self.ensureProtectedRuntimeProvisioned()
                }.value
                guard self.attempt === work, !work.cancelled else {
                    self.complete(work, .ended(VPNExitOutcome(status: 0)))
                    return
                }
                self.authenticate(work, password: password)
            } catch {
                self.complete(
                    work,
                    work.cancelled ? .ended(VPNExitOutcome(status: 0)) : .failed(error.localizedDescription)
                )
            }
        }
    }

    func stop(session: UUID) {
        guard let work = attempt, work.id == session else { return }
        work.cancelled = true
        work.setupTask?.cancel()
        if let auth = work.auth {
            auth.stop()
        } else if work.startingTunnel {
            let sessionString = session.uuidString
            DispatchQueue.global(qos: .userInitiated).async {
                Self.invokeHelperStop(session: sessionString)
            }
            work.tunnel?.stop()
        } else {
            complete(work, .ended(VPNExitOutcome(status: 0)))
        }
    }

    private func authenticate(_ work: Attempt, password: String) {
        guard !work.cancelled, attempt === work else { return }
        let server = work.config.normalizedServer
        guard TunnelRequest.validServer(server),
              TunnelRequest.protocols.contains(work.config.effectiveProtocol),
              !work.config.username.isEmpty,
              !work.config.username.contains("\0"),
              work.config.trimmedAuthGroup?.contains(where: { $0.isNewline || $0 == "\0" }) != true else {
            complete(work, .failed("Enter a valid HTTPS server, username and VPN protocol."))
            return
        }

        let auth = ManagedProcess(sessionID: work.id.uuidString)
        work.auth = auth
        work.receive(.connecting)
        var arguments = [
            "--authenticate", "--non-inter", "--passwd-on-stdin", "--no-system-trust",
            "--cafile=\(Self.effectiveCABundlePath())",
            "--protocol=\(work.config.effectiveProtocol)",
            "--user=\(work.config.username)"
        ]
        if let authGroup = work.config.trimmedAuthGroup {
            arguments.append("--authgroup=\(authGroup)")
        }
        arguments.append(contentsOf: ["--", server])
        auth.startWithOutcome(
            executable: SecureRuntime.executable,
            arguments: arguments,
            input: Data((password + "\n").utf8),
            environment: SecureRuntime.environment,
            started: {},
            stdout: { [weak self, weak work] data in
                DispatchQueue.main.async {
                    guard let self, let work, self.attempt === work else { return }
                    if work.authOutput.count + data.count > 262144 {
                        auth.stop()
                        self.complete(work, .failed("VPN authentication response is too large."))
                        return
                    }
                    // stdout contains the authentication cookie; never send it to visible logs.
                    work.authOutput.append(data)
                }
            },
            stderr: { [weak self, weak work] data in
                DispatchQueue.main.async {
                    guard let self, let work, self.attempt === work else { return }
                    work.receive(.output(data))
                }
            },
            exited: { [weak self, weak work] outcome in
                DispatchQueue.main.async {
                    guard let self, let work, self.attempt === work else { return }
                    work.auth = nil
                    if work.cancelled {
                        self.complete(work, .ended(outcome))
                        return
                    }
                    guard outcome.status == 0, outcome.cleanTermination else {
                        self.complete(work, .ended(outcome))
                        return
                    }
                    do {
                        let result = try AuthenticationResult(data: work.authOutput)
                        work.authOutput.removeAll()
                        let request = try result.request(
                            protocolType: work.config.effectiveProtocol,
                            originalServer: server
                        )
                        self.startTunnel(work, request: request)
                    } catch {
                        self.complete(work, .failed("Cannot read the VPN authentication result."))
                    }
                }
            },
            failed: { [weak self, weak work] message in
                DispatchQueue.main.async {
                    guard let self, let work else { return }
                    self.complete(work, .failed("Could not start VPN authentication: \(message)"))
                }
            }
        )
    }

    private func startTunnel(_ work: Attempt, request: TunnelRequest) {
        guard !work.cancelled, attempt === work else {
            complete(work, .ended(VPNExitOutcome(status: 0)))
            return
        }
        do {
            let requestData = try JSONEncoder().encode(request)
            work.startingTunnel = true
            work.receive(.tunnelStarting)

            let tunnel = ManagedProcess(
                sessionID: work.id.uuidString,
                gracefulTimeout: 15.0,
                logDrainTimeout: 1.5
            )
            work.tunnel = tunnel
            let sessionString = work.id.uuidString
            let invocation = Self.helperInvocation(arguments: [
                HelperConstants.tunnelSessionFlag,
                sessionString
            ])

            tunnel.startWithOutcome(
                executable: invocation.executable,
                arguments: invocation.arguments,
                input: requestData,
                environment: SecureRuntime.environment,
                started: { [weak work] in
                    DispatchQueue.main.async {
                        guard let work, work.cancelled else { return }
                        DispatchQueue.global(qos: .userInitiated).async {
                            Self.invokeHelperStop(session: sessionString)
                        }
                    }
                },
                stdout: { [weak self, weak work] data in
                    DispatchQueue.main.async {
                        guard let self, let work, self.attempt === work else { return }
                        if work.tunnelOutcomeData.count + data.count <= 65536 {
                            work.tunnelOutcomeData.append(data)
                        }
                    }
                },
                stderr: { [weak self, weak work] data in
                    DispatchQueue.main.async {
                        guard let self, let work, self.attempt === work else { return }
                        if let text = String(data: data, encoding: .utf8),
                           text.contains("LLVM Profile Error:") {
                            let filtered = text
                                .components(separatedBy: "\n")
                                .filter { !$0.hasPrefix("LLVM Profile Error:") }
                                .joined(separator: "\n")
                            if !filtered.isEmpty {
                                work.receive(.output(Data(filtered.utf8)))
                            }
                            return
                        }
                        work.receive(.output(data))
                    }
                },
                exited: { [weak self, weak work] wrapperOutcome in
                    DispatchQueue.main.async {
                        guard let self, let work, self.attempt === work else { return }
                        work.tunnel = nil
                        let finalOutcome: VPNExitOutcome
                        if let decoded = try? JSONDecoder().decode(VPNExitOutcome.self, from: work.tunnelOutcomeData) {
                            finalOutcome = VPNExitOutcome(
                                status: decoded.status,
                                processConfirmedStopped: decoded.processConfirmedStopped && wrapperOutcome.processConfirmedStopped,
                                wasForceKilled: decoded.wasForceKilled || wrapperOutcome.wasForceKilled,
                                logsComplete: decoded.logsComplete && wrapperOutcome.logsComplete,
                                networkCleanupComplete: decoded.networkCleanupComplete && wrapperOutcome.networkCleanupComplete
                            )
                        } else {
                            finalOutcome = wrapperOutcome
                        }
                        self.complete(work, .ended(finalOutcome))
                    }
                },
                failed: { [weak self, weak work] message in
                    DispatchQueue.main.async {
                        guard let self, let work else { return }
                        self.complete(work, .failed("Could not start VPN tunnel: \(message)"))
                    }
                }
            )
        } catch {
            complete(work, .failed(error.localizedDescription))
        }
    }

    private func complete(_ work: Attempt, _ event: VPNTransportEvent) {
        guard attempt === work else { return }
        attempt = nil
        work.setupTask = nil
        work.authOutput.removeAll()
        work.tunnelOutcomeData.removeAll()
        work.receive(event)
    }

    nonisolated private static let helperLock = NSLock()
    nonisolated private static let provisioningLock = NSLock()
    nonisolated private static let caBundleLock = NSLock()
    nonisolated(unsafe) private static var helperVerifiedInProcess = false
    nonisolated(unsafe) private static var cachedCABundleSignature: String?
    nonisolated(unsafe) private static var cachedCABundlePath: String?

    /// Merges the packaged Mozilla CA bundle with trusted certificates in macOS System.keychain
    /// so enterprise/internal VPN Root CAs are trusted without weakening certificate validation.
    nonisolated static func effectiveCABundlePath(
        baseCABundle: URL = SecureRuntime.caBundle,
        systemKeychainPath: String = "/Library/Keychains/System.keychain",
        customCertificatesPEM: String? = nil
    ) -> String {
        caBundleLock.lock()
        defer { caBundleLock.unlock() }

        let fm = FileManager.default
        guard let baseData = try? Data(contentsOf: baseCABundle), !baseData.isEmpty else {
            return baseCABundle.path
        }

        let baseMTime = (try? fm.attributesOfItem(atPath: baseCABundle.path)[.modificationDate] as? Date)?
            .timeIntervalSince1970 ?? 0
        let keychainMTime = (try? fm.attributesOfItem(atPath: systemKeychainPath)[.modificationDate] as? Date)?
            .timeIntervalSince1970 ?? 0
        let signature = "\(baseCABundle.path)|\(baseMTime)|\(systemKeychainPath)|\(keychainMTime)|\(customCertificatesPEM?.hashValue ?? 0)"

        let mergedURL = fm.temporaryDirectory
            .appendingPathComponent("OpenConnectGUI-ca-bundle-\(getuid()).pem")
        if customCertificatesPEM == nil,
           cachedCABundleSignature == signature,
           let cachedCABundlePath,
           fm.fileExists(atPath: cachedCABundlePath) {
            return cachedCABundlePath
        }

        let extraPEM: String
        if let customCertificatesPEM {
            extraPEM = customCertificatesPEM
        } else {
            extraPEM = exportKeychainCertificatesPEM(keychainPath: systemKeychainPath)
        }

        guard extraPEM.contains("-----BEGIN CERTIFICATE-----") else {
            cachedCABundleSignature = signature
            cachedCABundlePath = baseCABundle.path
            return baseCABundle.path
        }

        var combined = baseData
        if combined.last != UInt8(ascii: "\n") {
            combined.append(UInt8(ascii: "\n"))
        }
        combined.append(Data(extraPEM.utf8))

        do {
            try combined.write(to: mergedURL, options: .atomic)
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: mergedURL.path)
            if customCertificatesPEM == nil {
                cachedCABundleSignature = signature
                cachedCABundlePath = mergedURL.path
            }
            return mergedURL.path
        } catch {
            return baseCABundle.path
        }
    }

    nonisolated private static func exportKeychainCertificatesPEM(keychainPath: String) -> String {
        guard FileManager.default.fileExists(atPath: keychainPath),
              FileManager.default.isExecutableFile(atPath: "/usr/bin/security") else {
            return ""
        }
        let task = Process()
        let outPipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["find-certificate", "-a", "-p", keychainPath]
        task.environment = SecureRuntime.environment
        task.standardOutput = outPipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return "" }
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    nonisolated private static func helperInvocation(arguments: [String]) -> (executable: URL, arguments: [String]) {
        if SecureRuntime.isSetuidHelperInstalled {
            return (SecureRuntime.helper, arguments)
        }
        return (URL(fileURLWithPath: "/usr/bin/sudo"), ["-n", SecureRuntime.helper.path] + arguments)
    }

    nonisolated private static func invokeHelperStop(session: String) {
        let invocation = helperInvocation(arguments: [HelperConstants.stopSessionFlag, session])
        let stopTask = Process()
        stopTask.executableURL = invocation.executable
        stopTask.arguments = invocation.arguments
        stopTask.environment = SecureRuntime.environment
        stopTask.standardOutput = FileHandle.nullDevice
        stopTask.standardError = FileHandle.nullDevice
        do {
            try stopTask.run()
            stopTask.waitUntilExit()
        } catch {}
    }

    nonisolated static func isInstalledRuntimeMatchingBundle(
        bundledRuntime: URL = SecureRuntime.bundledRuntime,
        bundledHelper: URL = SecureRuntime.bundledHelper,
        installedRuntime: URL = SecureRuntime.runtime,
        installedHelper: URL = SecureRuntime.helper,
        requireAuthorizedCaller: Bool = true
    ) -> Bool {
        if requireAuthorizedCaller && !SecureRuntime.isCallerAuthorized(uid: getuid()) {
            return false
        }
        let fm = FileManager.default
        var pairs: [(URL, URL)] = [
            (bundledHelper, installedHelper),
            (bundledRuntime.appendingPathComponent("bin/openconnect"), installedRuntime.appendingPathComponent("bin/openconnect")),
            (bundledRuntime.appendingPathComponent("vpnc-script"), installedRuntime.appendingPathComponent("vpnc-script")),
            (bundledRuntime.appendingPathComponent("ca-bundle.pem"), installedRuntime.appendingPathComponent("ca-bundle.pem"))
        ]
        let bundledManifest = bundledRuntime.appendingPathComponent("build-manifest.json")
        if fm.fileExists(atPath: bundledManifest.path) {
            pairs.append((bundledManifest, installedRuntime.appendingPathComponent("build-manifest.json")))
        }
        let bundledLibDir = bundledRuntime.appendingPathComponent("lib", isDirectory: true)
        let installedLibDir = installedRuntime.appendingPathComponent("lib", isDirectory: true)
        if let bundledLibs = try? fm.contentsOfDirectory(atPath: bundledLibDir.path) {
            let bundledDylibs = bundledLibs.filter { $0.hasSuffix(".dylib") }.sorted()
            let installedDylibs = ((try? fm.contentsOfDirectory(atPath: installedLibDir.path)) ?? [])
                .filter { $0.hasSuffix(".dylib") }
                .sorted()
            guard bundledDylibs == installedDylibs else {
                return false
            }
            for dylib in bundledDylibs {
                pairs.append((
                    bundledLibDir.appendingPathComponent(dylib),
                    installedLibDir.appendingPathComponent(dylib)
                ))
            }
        }
        return pairs.allSatisfy { bundled, installed in
            fm.contentsEqual(atPath: bundled.path, andPath: installed.path)
        }
    }

    nonisolated private static func isHelperUpToDateAndReady() -> Bool {
        guard SecureRuntime.isSetuidHelperInstalled,
              (try? SecureRuntime.validateInstallation()) != nil,
              isInstalledRuntimeMatchingBundle() else {
            return false
        }
        helperLock.lock()
        let alreadyVerified = helperVerifiedInProcess
        helperLock.unlock()
        if alreadyVerified {
            return true
        }
        let invocation = helperInvocation(arguments: [HelperConstants.checkReadyFlag])
        let checkTask = Process()
        checkTask.executableURL = invocation.executable
        checkTask.arguments = invocation.arguments
        checkTask.environment = SecureRuntime.environment
        checkTask.standardOutput = FileHandle.nullDevice
        checkTask.standardError = FileHandle.nullDevice
        do {
            try checkTask.run()
            checkTask.waitUntilExit()
            let ready = checkTask.terminationStatus == 0
            if ready {
                helperLock.lock()
                helperVerifiedInProcess = true
                helperLock.unlock()
            }
            return ready
        } catch {
            return false
        }
    }

    nonisolated private static func ensureProtectedRuntimeProvisioned() throws {
        provisioningLock.lock()
        defer { provisioningLock.unlock() }

        let bundledHelper = SecureRuntime.bundledHelper
        let bundledRuntime = SecureRuntime.bundledRuntime

        guard FileManager.default.isExecutableFile(atPath: bundledHelper.path),
              FileManager.default.isExecutableFile(atPath: bundledRuntime.appendingPathComponent("bin/openconnect").path),
              FileManager.default.fileExists(atPath: bundledRuntime.appendingPathComponent("vpnc-script").path),
              FileManager.default.fileExists(atPath: bundledRuntime.appendingPathComponent("ca-bundle.pem").path) else {
            throw VPNServiceError.message("The OpenConnect runtime is missing from this application bundle.")
        }

        if isHelperUpToDateAndReady() {
            return
        }

        helperLock.lock()
        helperVerifiedInProcess = false
        helperLock.unlock()

        let username = NSUserName()
        let callerUID = getuid()
        let allowedCharset = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !username.isEmpty,
              callerUID > 0,
              username.unicodeScalars.allSatisfy({ allowedCharset.contains($0) }) else {
            throw VPNServiceError.message("Cannot provision the VPN helper for the current macOS account name.")
        }

        let quotedBundledRuntime = TunnelRequest.shellQuote(bundledRuntime.path)
        let quotedBundledHelper = TunnelRequest.shellQuote(bundledHelper.path)
        let sudoersLine = "\(username) ALL=(root) NOPASSWD: /Library/Application\\ Support/OpenConnectGUI/runtime/OpenConnectHelper"
        let quotedSudoersLine = TunnelRequest.shellQuote(sudoersLine)

        let script = [
            "set -eu",
            "umask 0022",
            "root_dir='/Library/Application Support/OpenConnectGUI'",
            "stage_dir=\"$root_dir/runtime.staging.$$\"",
            "old_dir=\"$root_dir/runtime.old.$$\"",
            "final_dir=\"$root_dir/runtime\"",
            "/bin/mkdir -p \"$root_dir\"",
            "/bin/rm -rf \"$stage_dir\" \"$old_dir\"",
            "/bin/mkdir -p \"$stage_dir\"",
            "/bin/cp -R \(quotedBundledRuntime) \"$stage_dir/OpenConnect\"",
            "/bin/cp \(quotedBundledHelper) \"$stage_dir/OpenConnectHelper\"",
            "printf '%s\\n' '\(callerUID)' > \"$stage_dir/authorized-uid\"",
            "/usr/sbin/chown root:wheel \"$root_dir\"",
            "/bin/chmod -N \"$root_dir\" || true",
            "/bin/chmod 0755 \"$root_dir\"",
            "/usr/sbin/chown -R root:wheel \"$stage_dir\"",
            "/bin/chmod -RN \"$stage_dir\" || true",
            "/bin/chmod -R u+rwX,go+rX,go-w \"$stage_dir\"",
            "/bin/chmod 0644 \"$stage_dir/authorized-uid\"",
            "/bin/chmod 0755 \"$stage_dir/OpenConnect/bin/openconnect\" \"$stage_dir/OpenConnect/vpnc-script\"",
            "/bin/chmod 4755 \"$stage_dir/OpenConnectHelper\"",
            "if [ -d \"$final_dir\" ]; then /bin/mv \"$final_dir\" \"$old_dir\"; fi",
            "/bin/mv \"$stage_dir\" \"$final_dir\"",
            "/bin/rm -rf \"$old_dir\"",
            "/bin/mkdir -p /private/var/run/OpenConnectGUI",
            "/usr/sbin/chown root:wheel /private/var/run/OpenConnectGUI",
            "/bin/chmod 0700 /private/var/run/OpenConnectGUI",
            "printf '%s\\n' \(quotedSudoersLine) > /private/etc/sudoers.d/openconnectgui.tmp",
            "/usr/sbin/chown root:wheel /private/etc/sudoers.d/openconnectgui.tmp",
            "/bin/chmod 0440 /private/etc/sudoers.d/openconnectgui.tmp",
            "/usr/sbin/visudo -cf /private/etc/sudoers.d/openconnectgui.tmp",
            "/bin/cp /private/etc/sudoers.d/openconnectgui.tmp /private/etc/sudoers.d/zz-openconnectgui",
            "/usr/sbin/chown root:wheel /private/etc/sudoers.d/zz-openconnectgui",
            "/bin/chmod 0440 /private/etc/sudoers.d/zz-openconnectgui",
            "/bin/mv /private/etc/sudoers.d/openconnectgui.tmp /private/etc/sudoers.d/openconnectgui",
            "\"$final_dir/OpenConnectHelper\" --check-ready"
        ].joined(separator: " && ")

        let escapedForAppleScript = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")

        let authTask = Process()
        authTask.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        authTask.arguments = [
            "-e",
            "do shell script \"\(escapedForAppleScript)\" with administrator privileges"
        ]
        let errPipe = Pipe()
        authTask.standardOutput = FileHandle.nullDevice
        authTask.standardError = errPipe

        try authTask.run()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        authTask.waitUntilExit()
        guard authTask.terminationStatus == 0 else {
            let errText = String(data: errData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if errText.contains("(-128)") || errText.localizedCaseInsensitiveContains("User canceled") {
                throw VPNServiceError.message("Administrator authorization was cancelled.")
            }
            if !errText.isEmpty {
                throw VPNServiceError.message("Administrator setup failed: \(errText)")
            }
            throw VPNServiceError.message("Administrator authorization was cancelled or failed.")
        }
        helperLock.lock()
        helperVerifiedInProcess = true
        helperLock.unlock()
    }
}
