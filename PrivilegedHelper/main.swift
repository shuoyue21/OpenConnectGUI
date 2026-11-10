import Darwin
import Foundation

private func elevateToRootIfPossible() -> Bool {
    let callerUID = getuid()
    guard SecureRuntime.isCallerAuthorized(uid: callerUID) else {
        return false
    }
    if geteuid() == 0 {
        if getgid() != 0 { _ = setgid(0) }
        if getuid() != 0 { _ = setuid(0) }
    }
    return getuid() == 0 && geteuid() == 0
}

private func parentPID(of pid: pid_t) -> pid_t? {
    guard pid > 1 else { return nil }
    var info = proc_bsdinfo()
    let size = MemoryLayout<proc_bsdinfo>.stride
    let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
    guard ret == Int32(size), info.pbi_status != SIDL, info.pbi_status != SZOMB else {
        return nil
    }
    return pid_t(info.pbi_ppid)
}

private func isSudoProcess(pid: pid_t) -> Bool {
    guard pid > 1 else { return false }
    var info = proc_bsdinfo()
    let size = MemoryLayout<proc_bsdinfo>.stride
    let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
    guard ret == Int32(size), info.pbi_status != SIDL, info.pbi_status != SZOMB else {
        return false
    }
    let comm = withUnsafeBytes(of: info.pbi_comm) { raw -> String in
        let bytes = raw.prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }
    return comm == "sudo"
}

private func isStdoutPipePeerClosed() -> Bool {
    var pfd = pollfd(fd: STDOUT_FILENO, events: 0, revents: 0)
    guard Darwin.poll(&pfd, 1, 0) > 0 else { return false }
    return (pfd.revents & Int16(POLLHUP | POLLERR | POLLNVAL)) != 0
}

private func reapStaleSessions(excluding activeSession: String? = nil) {
    let fm = FileManager.default
    let runDir = SecureRuntime.sessionRunDir
    guard let entries = try? fm.contentsOfDirectory(
        at: runDir,
        includingPropertiesForKeys: [.contentModificationDateKey]
    ) else { return }

    var activeSessionIDs: Set<String> = []
    if let activeSession {
        activeSessionIDs.insert(activeSession)
    }

    for entry in entries {
        let name = entry.lastPathComponent
        guard name.hasPrefix("supervisor-"), name.hasSuffix(".json") else { continue }
        let sessionID = String(name.dropFirst("supervisor-".count).dropLast(".json".count))
        guard sessionID != activeSession else { continue }

        if let data = try? Data(contentsOf: entry),
           let lease = try? JSONDecoder().decode(VPNScriptLease.self, from: data),
           lease.sessionID == sessionID {
            let supervisorAlive = VPNScriptRunner.isOwnedProcessAlive(
                pid: lease.runnerPID,
                expectedPGID: nil,
                expectedStartTimeSec: lease.startTimeSec
            )
            let parentAlive = lease.parentPID > 1 && kill(lease.parentPID, 0) == 0
            if supervisorAlive && parentAlive {
                activeSessionIDs.insert(sessionID)
                continue
            }

            let sessionDir = runDir.appendingPathComponent("session-\(sessionID)", isDirectory: true)
            if let leaseFiles = try? fm.contentsOfDirectory(at: sessionDir, includingPropertiesForKeys: nil) {
                for file in leaseFiles where file.lastPathComponent.hasPrefix("lease-") && file.pathExtension == "json" {
                    if let scriptData = try? Data(contentsOf: file),
                       let scriptLease = try? JSONDecoder().decode(VPNScriptLease.self, from: scriptData) {
                        if scriptLease.pgid > 1 { _ = kill(-scriptLease.pgid, SIGKILL) }
                        if VPNScriptRunner.isOwnedProcessAlive(
                            pid: scriptLease.runnerPID,
                            expectedPGID: scriptLease.pgid,
                            expectedStartTimeSec: scriptLease.startTimeSec
                        ) {
                            _ = kill(scriptLease.runnerPID, SIGKILL)
                        }
                    }
                }
            }
            if supervisorAlive {
                _ = kill(lease.runnerPID, SIGTERM)
                usleep(100_000)
                if VPNScriptRunner.isOwnedProcessAlive(
                    pid: lease.runnerPID,
                    expectedPGID: nil,
                    expectedStartTimeSec: lease.startTimeSec
                ) {
                    _ = kill(lease.runnerPID, SIGKILL)
                }
            }
            try? fm.removeItem(at: sessionDir)
            try? fm.removeItem(at: runDir.appendingPathComponent("cancelled-\(sessionID)"))
        }
        try? fm.removeItem(at: entry)
    }

    let now = Date()
    for entry in entries {
        let name = entry.lastPathComponent
        let sessionID: String?
        if name.hasPrefix("session-") {
            sessionID = String(name.dropFirst("session-".count))
        } else if name.hasPrefix("cancelled-") {
            sessionID = String(name.dropFirst("cancelled-".count))
        } else {
            sessionID = nil
        }
        guard let sessionID, !activeSessionIDs.contains(sessionID) else { continue }
        let mtime = (try? entry.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        if let mtime, now.timeIntervalSince(mtime) < 60 {
            continue
        }
        try? fm.removeItem(at: entry)
    }
}

@discardableResult
private func writeAll(fd: Int32, data: Data) -> Bool {
    data.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return true }
        var offset = 0
        while offset < rawBuffer.count {
            let written = Darwin.write(fd, base.advanced(by: offset), rawBuffer.count - offset)
            if written > 0 {
                offset += written
            } else if written < 0 && errno == EINTR {
                continue
            } else {
                return false
            }
        }
        return true
    }
}

private func readStdinBounded(maxBytes: Int) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(STDIN_FILENO, $0.baseAddress, $0.count)
        }
        if count > 0 {
            if result.count + count > maxBytes {
                throw VPNServiceError.invalidRequest
            }
            result.append(contentsOf: buffer.prefix(count))
        } else if count == 0 {
            break
        } else if errno == EINTR {
            continue
        } else {
            throw VPNServiceError.invalidRequest
        }
    }
    return result
}

private func runTunnelSession(_ session: String) -> Never {
    do {
        guard elevateToRootIfPossible() else {
            throw VPNServiceError.message("The VPN tunnel helper must run as root.")
        }
        guard UUID(uuidString: session) != nil else {
            throw VPNServiceError.invalidRequest
        }
        try SecureRuntime.validateInstallation()

        let requestData = try readStdinBounded(maxBytes: 131072)
        let request = try JSONDecoder().decode(TunnelRequest.self, from: requestData)
        try request.validate()

        let runDir = SecureRuntime.sessionRunDir
        try FileManager.default.createDirectory(
            at: runDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        reapStaleSessions(excluding: session)
        let supervisorURL = runDir.appendingPathComponent("supervisor-\(session).json")
        let cancelledURL = runDir.appendingPathComponent("cancelled-\(session)")

        if FileManager.default.fileExists(atPath: cancelledURL.path) {
            try? FileManager.default.removeItem(at: cancelledURL)
            if let encoded = try? JSONEncoder().encode(VPNExitOutcome(status: 0)) {
                writeAll(fd: STDOUT_FILENO, data: encoded)
            }
            exit(0)
        }

        let pid = getpid()
        let pgid = getpgrp()
        let initialParentPID = getppid()
        let initialGrandparentPID = isSudoProcess(pid: initialParentPID) ? (parentPID(of: initialParentPID) ?? 0) : 0
        let startTime = VPNScriptRunner.processStartTimeSec(pid: pid) ?? UInt64(Date().timeIntervalSince1970)
        let lease = VPNScriptLease(
            sessionID: session,
            runnerPID: pid,
            pgid: pgid,
            parentPID: initialParentPID,
            reason: "supervisor",
            startTimeSec: startTime
        )
        try JSONEncoder().encode(lease).write(to: supervisorURL, options: .atomic)

        let child = ManagedProcess(
            sessionID: session,
            stateDirectory: runDir.appendingPathComponent("session-\(session)", isDirectory: true)
        )
        signal(SIGPIPE, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termSource.setEventHandler { child.stop() }
        termSource.resume()
        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        intSource.setEventHandler { child.stop() }
        intSource.resume()

        // Monitor GUI parent process liveness and stdout pipe hangup so a crashed/force-quit GUI never leaves an orphaned root tunnel.
        let parentWatchdog = DispatchSource.makeTimerSource(queue: .main)
        parentWatchdog.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        parentWatchdog.setEventHandler {
            let parentDead = initialParentPID <= 1 || getppid() != initialParentPID || kill(initialParentPID, 0) != 0
            let grandparentDead = initialGrandparentPID > 1 && (
                parentPID(of: initialParentPID) != initialGrandparentPID ||
                kill(initialGrandparentPID, 0) != 0
            )
            if parentDead || grandparentDead || isStdoutPipePeerClosed() {
                parentWatchdog.cancel()
                child.stop()
            }
        }
        parentWatchdog.resume()

        // Re-check cancellation right after recording the supervisor lease.
        if FileManager.default.fileExists(atPath: cancelledURL.path) {
            child.stop()
        }

        child.startWithOutcome(
            executable: SecureRuntime.executable,
            arguments: request.arguments(
                scriptRunner: SecureRuntime.helper.path,
                caFile: SecureRuntime.caBundle.path
            ),
            input: Data((request.cookie + "\n").utf8),
            environment: SecureRuntime.environment,
            started: {},
            stdout: { data in
                if !writeAll(fd: STDERR_FILENO, data: data) {
                    child.stop()
                }
            },
            stderr: { data in
                if !writeAll(fd: STDERR_FILENO, data: data) {
                    child.stop()
                }
            },
            exited: { outcome in
                parentWatchdog.cancel()
                try? FileManager.default.removeItem(at: supervisorURL)
                try? FileManager.default.removeItem(at: cancelledURL)
                if let encoded = try? JSONEncoder().encode(outcome) {
                    writeAll(fd: STDOUT_FILENO, data: encoded)
                }
                exit(outcome.status == 0 ? 0 : 1)
            },
            failed: { message in
                parentWatchdog.cancel()
                try? FileManager.default.removeItem(at: supervisorURL)
                try? FileManager.default.removeItem(at: cancelledURL)
                writeAll(fd: STDERR_FILENO, data: Data((message + "\n").utf8))
                exit(1)
            }
        )

        RunLoop.current.run()
        withExtendedLifetime((termSource, intSource, parentWatchdog)) {}
        exit(0)
    } catch {
        writeAll(fd: STDERR_FILENO, data: Data(("OpenConnectHelper: \(error.localizedDescription)\n").utf8))
        exit(1)
    }
}

private func stopTunnelSession(_ session: String) -> Never {
    guard elevateToRootIfPossible(), UUID(uuidString: session) != nil else {
        fputs("OpenConnectHelper: invalid stop request.\n", stderr)
        exit(2)
    }
    let runDir = SecureRuntime.sessionRunDir
    try? FileManager.default.createDirectory(
        at: runDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    let cancelledURL = runDir.appendingPathComponent("cancelled-\(session)")
    try? Data("1".utf8).write(to: cancelledURL, options: .atomic)

    let supervisorURL = runDir.appendingPathComponent("supervisor-\(session).json")
    if let data = try? Data(contentsOf: supervisorURL),
       let lease = try? JSONDecoder().decode(VPNScriptLease.self, from: data),
       lease.sessionID == session,
       VPNScriptRunner.isOwnedProcessAlive(
           pid: lease.runnerPID,
           expectedPGID: nil,
           expectedStartTimeSec: lease.startTimeSec
       ) {
        _ = kill(lease.runnerPID, SIGTERM)

        // Wait up to 7.5s for the supervisor to complete graceful teardown; escalate to root SIGKILL if wedged.
        let deadline = Date().addingTimeInterval(7.5)
        while Date() < deadline {
            if !VPNScriptRunner.isOwnedProcessAlive(
                pid: lease.runnerPID,
                expectedPGID: nil,
                expectedStartTimeSec: lease.startTimeSec
            ) {
                exit(0)
            }
            usleep(50_000)
        }

        let sessionDir = runDir.appendingPathComponent("session-\(session)", isDirectory: true)
        if let files = try? FileManager.default.contentsOfDirectory(at: sessionDir, includingPropertiesForKeys: nil) {
            for file in files where file.lastPathComponent.hasPrefix("lease-") && file.pathExtension == "json" {
                if let scriptData = try? Data(contentsOf: file),
                   let scriptLease = try? JSONDecoder().decode(VPNScriptLease.self, from: scriptData),
                   scriptLease.sessionID == session {
                    if scriptLease.pgid > 1 { _ = kill(-scriptLease.pgid, SIGKILL) }
                    if VPNScriptRunner.isOwnedProcessAlive(
                        pid: scriptLease.runnerPID,
                        expectedPGID: scriptLease.pgid,
                        expectedStartTimeSec: scriptLease.startTimeSec
                    ) {
                        _ = kill(scriptLease.runnerPID, SIGKILL)
                    }
                }
            }
        }
        if VPNScriptRunner.isOwnedProcessAlive(
            pid: lease.runnerPID,
            expectedPGID: nil,
            expectedStartTimeSec: lease.startTimeSec
        ) {
            _ = kill(lease.runnerPID, SIGKILL)
        }
        try? FileManager.default.removeItem(at: supervisorURL)
        try? FileManager.default.removeItem(at: cancelledURL)
    }
    exit(0)
}

let args = Array(CommandLine.arguments.dropFirst())
if args == [HelperConstants.checkReadyFlag] {
    do {
        guard elevateToRootIfPossible() else {
            throw VPNServiceError.message("The VPN helper must run as root.")
        }
        try SecureRuntime.validateInstallation()
        reapStaleSessions()
        exit(0)
    } catch {
        fputs("OpenConnectHelper: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else if VPNScriptRunner.validateArguments(CommandLine.arguments) {
    do {
        guard elevateToRootIfPossible() else {
            throw VPNServiceError.message("The network script runner must run as root.")
        }
        try SecureRuntime.validateInstallation()
        exit(VPNScriptRunner.executeFixedScript(scriptURL: SecureRuntime.script))
    } catch {
        fputs("OpenConnectHelper script runner: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else if args.count == 2 && args[0] == HelperConstants.tunnelSessionFlag {
    runTunnelSession(args[1])
} else if args.count == 2 && args[0] == HelperConstants.stopSessionFlag {
    stopTunnelSession(args[1])
} else {
    fputs("OpenConnectHelper: unsupported arguments.\n", stderr)
    exit(2)
}
