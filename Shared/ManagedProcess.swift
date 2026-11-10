import Darwin
import Foundation

/// Owns one main VPN process plus its session-scoped network script process groups.
/// Coordinates 4-stage teardown: graceful TERM -> script & process wait -> owned PGID/PID cleanup -> bounded log drain.
final class ManagedProcess {
    private let queue = DispatchQueue(label: "OpenConnectGUI.process")
    let sessionID: String
    let stateDirectory: URL
    let gracefulTimeout: TimeInterval
    let scriptKillGrace: TimeInterval
    let logDrainTimeout: TimeInterval
    let scriptTimeout: TimeInterval

    private var process: Process?
    private var stopped = false
    private var launched = false
    private var deliveredExit = false
    private var status: Int32?
    private var wasForceKilled = false
    private var scriptWasForceTerminated = false
    private var scriptsFinished = false
    private var logsComplete = true
    private var drainTimerStarted = false
    private var openReaders = 0
    private var readSources: [DispatchSourceRead] = []
    private var onOutcome: ((VPNExitOutcome) -> Void)?
    private var stderrCallback: ((Data) -> Void)?

    init(
        sessionID: String = UUID().uuidString,
        stateDirectory: URL? = nil,
        gracefulTimeout: TimeInterval = 5.0,
        scriptKillGrace: TimeInterval = 0.2,
        logDrainTimeout: TimeInterval = 1.0,
        scriptTimeout: TimeInterval = 10.0
    ) {
        self.sessionID = sessionID
        self.stateDirectory = stateDirectory ?? FileManager.default.temporaryDirectory
            .appendingPathComponent("OpenConnectGUI-session-\(sessionID)", isDirectory: true)
        self.gracefulTimeout = gracefulTimeout
        self.scriptKillGrace = scriptKillGrace
        self.logDrainTimeout = logDrainTimeout
        self.scriptTimeout = scriptTimeout
    }

    static func cleanupStaleTemporaryDirectories(maxAge: TimeInterval = 300) {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
        guard let entries = try? fm.contentsOfDirectory(
            at: tempDir,
            includingPropertiesForKeys: [.isDirectoryKey, .contentModificationDateKey]
        ) else { return }
        let now = Date()
        for entry in entries where entry.lastPathComponent.hasPrefix("OpenConnectGUI-session-") {
            guard let values = try? entry.resourceValues(forKeys: [.isDirectoryKey, .contentModificationDateKey]),
                  values.isDirectory == true,
                  let mtime = values.contentModificationDate,
                  now.timeIntervalSince(mtime) >= maxAge else {
                continue
            }
            let leaseFiles = (try? fm.contentsOfDirectory(at: entry, includingPropertiesForKeys: nil)) ?? []
            let hasLiveProcess = leaseFiles.contains { file in
                guard file.lastPathComponent.hasPrefix("lease-"),
                      file.pathExtension == "json",
                      let data = try? Data(contentsOf: file),
                      let lease = try? JSONDecoder().decode(VPNScriptLease.self, from: data) else {
                    return false
                }
                return VPNScriptRunner.isOwnedProcessAlive(
                    pid: lease.runnerPID,
                    expectedPGID: lease.pgid,
                    expectedStartTimeSec: lease.startTimeSec
                )
            }
            if !hasLiveProcess {
                try? fm.removeItem(at: entry)
            }
        }
    }

    func start(
        executable: URL,
        arguments: [String],
        input: Data,
        environment: [String: String],
        started: @escaping () -> Void,
        stdout: @escaping (Data) -> Void,
        stderr: @escaping (Data) -> Void,
        exited: @escaping (Int32) -> Void,
        failed: @escaping (String) -> Void
    ) {
        startWithOutcome(
            executable: executable,
            arguments: arguments,
            input: input,
            environment: environment,
            started: started,
            stdout: stdout,
            stderr: stderr,
            exited: { outcome in exited(outcome.status) },
            failed: failed
        )
    }

    func startWithOutcome(
        executable: URL,
        arguments: [String],
        input: Data,
        environment: [String: String],
        started: @escaping () -> Void,
        stdout: @escaping (Data) -> Void,
        stderr: @escaping (Data) -> Void,
        exited: @escaping (VPNExitOutcome) -> Void,
        failed: @escaping (String) -> Void
    ) {
        queue.async {
            guard !self.launched else { return }
            self.launched = true
            guard !self.stopped else {
                exited(VPNExitOutcome(status: 0))
                return
            }

            do {
                try FileManager.default.createDirectory(
                    at: self.stateDirectory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                failed("Cannot create session directory: \(error.localizedDescription)")
                return
            }

            let child = Process()
            let output = Pipe()
            let errors = Pipe()
            let stdin = Pipe()
            var mergedEnv = environment
            mergedEnv[VPNScriptRunner.sessionIDEnv] = self.sessionID
            mergedEnv[VPNScriptRunner.stateDirEnv] = self.stateDirectory.path
            mergedEnv[VPNScriptRunner.scriptTimeoutEnv] = String(self.scriptTimeout)

            child.executableURL = executable
            child.arguments = arguments
            child.environment = mergedEnv
            child.currentDirectoryURL = URL(fileURLWithPath: "/")
            child.standardOutput = output
            child.standardError = errors
            child.standardInput = stdin
            self.onOutcome = exited
            self.stderrCallback = stderr

            child.terminationHandler = { [weak owner = self] terminated in
                guard let self = owner else { return }
                self.queue.async {
                    self.status = terminated.terminationStatus
                    self.awaitScriptsAfterMainExit(deadline: Date().addingTimeInterval(self.gracefulTimeout))
                }
            }
            self.process = child

            do {
                // An early-exiting child must produce EPIPE, not terminate the GUI/helper via SIGPIPE.
                guard fcntl(stdin.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                try child.run()
                // The parent must not retain the child's ends, otherwise EOF is never observable.
                try? output.fileHandleForWriting.close()
                try? errors.fileHandleForWriting.close()
                try? stdin.fileHandleForReading.close()

                self.openReaders = 2
                self.attachCancellableReader(output.fileHandleForReading, receive: stdout)
                self.attachCancellableReader(errors.fileHandleForReading, receive: stderr)
                started()

                DispatchQueue.global(qos: .userInitiated).async {
                    do { try stdin.fileHandleForWriting.write(contentsOf: input) } catch {
                        // child may already have exited
                    }
                    try? stdin.fileHandleForWriting.close()
                }
            } catch {
                self.process = nil
                self.onOutcome = nil
                self.stderrCallback = nil
                for handle in [
                    output.fileHandleForReading, output.fileHandleForWriting,
                    errors.fileHandleForReading, errors.fileHandleForWriting,
                    stdin.fileHandleForReading, stdin.fileHandleForWriting,
                ] { try? handle.close() }
                try? FileManager.default.removeItem(at: self.stateDirectory)
                failed(error.localizedDescription)
            }
        }
    }

    func stop() {
        queue.async {
            self.stopped = true
            guard let child = self.process, child.isRunning else { return }
            // Stage 1: Request graceful OpenConnect shutdown so it can invoke vpnc-script disconnect.
            child.terminate()

            // Stage 2 & 3: Wait up to gracefulTimeout, then force-kill owned main process and script process groups.
            self.queue.asyncAfter(deadline: .now() + self.gracefulTimeout) { [weak owner = self, weak child] in
                guard let self = owner, !self.deliveredExit else { return }
                if let child, self.process === child, child.isRunning {
                    self.wasForceKilled = true
                    kill(child.processIdentifier, SIGKILL)
                }
                self.terminateOwnedScripts {
                    if self.status == nil, let child, !child.isRunning {
                        self.status = child.terminationStatus
                    }
                    self.scriptsFinished = true
                    self.startLogDrainTimerIfNeeded()
                    self.finishIfReady()
                }
            }
        }
    }

    private func attachCancellableReader(_ handle: FileHandle, receive: @escaping (Data) -> Void) {
        let fd = handle.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        if flags != -1 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        var closed = false
        source.setEventHandler { [weak self] in
            guard self != nil, !closed else { return }
            var buffer = [UInt8](repeating: 0, count: 8192)
            while true {
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.read(fd, $0.baseAddress, $0.count)
                }
                if count > 0 {
                    receive(Data(buffer.prefix(count)))
                } else if count == 0 {
                    source.cancel()
                    break
                } else {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    source.cancel()
                    break
                }
            }
        }
        source.setCancelHandler { [weak self] in
            guard !closed else { return }
            closed = true
            try? handle.close()
            guard let self else { return }
            self.openReaders = max(0, self.openReaders - 1)
            self.finishIfReady()
        }
        readSources.append(source)
        source.resume()
    }

    private func awaitScriptsAfterMainExit(deadline: Date) {
        guard !deliveredExit else { return }
        let activeLeases = currentOwnedActiveLeases()
        if activeLeases.isEmpty {
            scriptsFinished = true
            startLogDrainTimerIfNeeded()
            finishIfReady()
            return
        }
        if Date() >= deadline {
            terminateOwnedScripts {
                self.scriptsFinished = true
                self.startLogDrainTimerIfNeeded()
                self.finishIfReady()
            }
            return
        }
        queue.asyncAfter(deadline: .now() + 0.025) { [weak self] in
            self?.awaitScriptsAfterMainExit(deadline: deadline)
        }
    }

    private func currentOwnedActiveLeases() -> [VPNScriptLease] {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: stateDirectory,
            includingPropertiesForKeys: nil
        ) else { return [] }
        var leases: [VPNScriptLease] = []
        for file in files where file.lastPathComponent.hasPrefix("lease-") && file.pathExtension == "json" {
            guard let data = try? Data(contentsOf: file),
                  let lease = try? JSONDecoder().decode(VPNScriptLease.self, from: data),
                  lease.sessionID == sessionID else { continue }
            if VPNScriptRunner.isOwnedProcessAlive(
                pid: lease.runnerPID,
                expectedPGID: lease.pgid,
                expectedStartTimeSec: lease.startTimeSec
            ) || isProcessGroupAlive(pgid: lease.pgid) {
                leases.append(lease)
            } else {
                try? FileManager.default.removeItem(at: file)
            }
        }
        return leases
    }

    private func isProcessGroupAlive(pgid: pid_t) -> Bool {
        guard pgid > 1 else { return false }
        if kill(-pgid, 0) == 0 { return true }
        return errno == EPERM
    }

    private func terminateOwnedScripts(completion: @escaping () -> Void) {
        let leases = currentOwnedActiveLeases()
        guard !leases.isEmpty else {
            completion()
            return
        }
        scriptWasForceTerminated = true
        for lease in leases {
            if lease.pgid > 1 { _ = kill(-lease.pgid, SIGTERM) }
            if VPNScriptRunner.isOwnedProcessAlive(
                pid: lease.runnerPID,
                expectedPGID: lease.pgid,
                expectedStartTimeSec: lease.startTimeSec
            ) {
                _ = kill(lease.runnerPID, SIGTERM)
            }
        }
        queue.asyncAfter(deadline: .now() + scriptKillGrace) { [weak self] in
            guard let self else {
                completion()
                return
            }
            for lease in self.currentOwnedActiveLeases() {
                if lease.pgid > 1 { _ = kill(-lease.pgid, SIGKILL) }
                if VPNScriptRunner.isOwnedProcessAlive(
                    pid: lease.runnerPID,
                    expectedPGID: lease.pgid,
                    expectedStartTimeSec: lease.startTimeSec
                ) {
                    _ = kill(lease.runnerPID, SIGKILL)
                }
            }
            self.waitForScriptReap(deadline: Date().addingTimeInterval(0.25), completion: completion)
        }
    }

    private func waitForScriptReap(deadline: Date, completion: @escaping () -> Void) {
        if currentOwnedActiveLeases().isEmpty || Date() >= deadline {
            completion()
            return
        }
        queue.asyncAfter(deadline: .now() + 0.015) { [weak self] in
            guard let self else {
                completion()
                return
            }
            self.waitForScriptReap(deadline: deadline, completion: completion)
        }
    }

    // Stage 4: Bound log draining after main process and scripts have exited, even if a grandchild holds pipe write ends.
    private func startLogDrainTimerIfNeeded() {
        guard status != nil, scriptsFinished, openReaders > 0, !drainTimerStarted, !deliveredExit else { return }
        drainTimerStarted = true
        queue.asyncAfter(deadline: .now() + logDrainTimeout) { [weak self] in
            guard let self, !self.deliveredExit, self.openReaders > 0 else { return }
            self.logsComplete = false
            self.stderrCallback?(Data("\n[Log output truncated: pipe remained open after process exit]\n".utf8))
            for source in self.readSources {
                source.cancel()
            }
            self.readSources.removeAll()
        }
    }

    private func finishIfReady() {
        guard let status, scriptsFinished, openReaders == 0, !deliveredExit else { return }
        deliveredExit = true
        let childStillRunning = process?.isRunning ?? false
        let remainingLeases = currentOwnedActiveLeases()
        let processConfirmedStopped = !childStillRunning && remainingLeases.isEmpty

        let disconnectStarted = FileManager.default.fileExists(
            atPath: stateDirectory.appendingPathComponent("disconnect-started").path
        )
        let disconnectCompleted = FileManager.default.fileExists(
            atPath: stateDirectory.appendingPathComponent("disconnect-completed").path
        )
        let scriptTimeoutMarker = FileManager.default.fileExists(
            atPath: stateDirectory.appendingPathComponent("script-forced-termination").path
        )
        let forcedScript = scriptWasForceTerminated || scriptTimeoutMarker
        let networkCleanupComplete = processConfirmedStopped &&
            !wasForceKilled &&
            !forcedScript &&
            (!disconnectStarted || disconnectCompleted)

        try? FileManager.default.removeItem(at: stateDirectory)
        readSources.removeAll()
        process?.terminationHandler = nil
        process = nil
        let callback = onOutcome
        onOutcome = nil
        stderrCallback = nil
        callback?(
            VPNExitOutcome(
                status: status,
                processConfirmedStopped: processConfirmedStopped,
                wasForceKilled: wasForceKilled || forcedScript,
                logsComplete: logsComplete,
                networkCleanupComplete: networkCleanupComplete
            )
        )
    }
}
