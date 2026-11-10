import Darwin
import Foundation

// The service never accepts command lines, executable paths, or caller-supplied PIDs.
enum HelperConstants {
    static let identifier = "mjucha.OpenconnectGUI.helper"
    static let plistName = identifier + ".plist"
    static let installedApp = URL(
        fileURLWithPath: "/Library/Application Support/OpenConnectGUI/OpenconnectGUI.app")
    static let helperRelativePath = "Contents/Library/HelperTools/OpenConnectHelper"
    static let runtimeRelativePath = "Contents/Resources/OpenConnect"
    static let scriptRunnerFlag = "--vpnc-script-runner"
    static let checkReadyFlag = "--check-ready"
    static let tunnelSessionFlag = "--tunnel-session"
    static let stopSessionFlag = "--stop-session"
}

struct VPNExitOutcome: Codable, Equatable, Sendable {
    let status: Int32
    let processConfirmedStopped: Bool
    let wasForceKilled: Bool
    let logsComplete: Bool
    let networkCleanupComplete: Bool

    init(
        status: Int32,
        processConfirmedStopped: Bool = true,
        wasForceKilled: Bool = false,
        logsComplete: Bool = true,
        networkCleanupComplete: Bool = true
    ) {
        self.status = status
        self.processConfirmedStopped = processConfirmedStopped
        self.wasForceKilled = wasForceKilled
        self.logsComplete = logsComplete
        self.networkCleanupComplete = networkCleanupComplete
    }

    var cleanTermination: Bool {
        processConfirmedStopped && !wasForceKilled && networkCleanupComplete
    }
}

@objc protocol VPNHelperProtocol {
    func start(session: String, request: Data, withReply reply: @escaping (String?) -> Void)
    func stop(session: String, withReply reply: @escaping (String?) -> Void)
    func migrateLegacyRule(withReply reply: @escaping (String?) -> Void)
}

@objc protocol VPNHelperEvents {
    func output(session: String, data: Data)
    func exited(session: String, outcome: Data)
}

struct TunnelRequest: Codable, Equatable, Sendable {
    let server: String
    let protocolType: String
    let cookie: String
    let fingerprint: String
    let resolve: String?

    static let protocols: Set<String> = [
        "anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array",
    ]

    func validate() throws {
        guard Self.protocols.contains(protocolType),
              Self.validServer(server),
              !cookie.isEmpty, cookie.utf8.count <= 65536,
              !cookie.contains(where: { $0.isNewline || $0 == "\0" }),
              fingerprint.range(
                of: #"^(pin-sha256:[A-Za-z0-9+/=]+|sha256:[0-9A-Fa-f]+|sha1:[0-9A-Fa-f]+)$"#,
                options: .regularExpression) != nil,
              fingerprint.count <= 256
        else { throw VPNServiceError.invalidRequest }
        if let resolve {
            guard resolve.count <= 1024,
                  resolve.range(of: #"^[A-Za-z0-9.\-\[\]:]+$"#, options: .regularExpression) != nil,
                  resolve.contains(":")
            else { throw VPNServiceError.invalidRequest }
        }
    }

    static func normalizeServer(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "https://" }
        let scheme: String
        let rest: String
        if let range = trimmed.range(of: "://") {
            scheme = trimmed[..<range.lowerBound].lowercased()
            rest = String(trimmed[range.upperBound...])
        } else {
            scheme = "https"
            rest = trimmed
        }
        let authority: String
        let pathSuffix: String
        if let slash = rest.firstIndex(of: "/") {
            authority = String(rest[..<slash])
            pathSuffix = String(rest[slash...])
        } else {
            authority = rest
            pathSuffix = ""
        }
        let colonCount = authority.reduce(into: 0) { count, ch in
            if ch == ":" { count += 1 }
        }
        let normalizedAuthority = (!authority.hasPrefix("[") && colonCount >= 2)
            ? "[\(authority)]"
            : authority
        return "\(scheme)://\(normalizedAuthority)\(pathSuffix)"
    }

    static func validServer(_ server: String) -> Bool {
        guard server.utf8.count <= 4096,
              !server.contains(where: { $0.isWhitespace || $0.isNewline || $0 == "\0" }),
              let parts = URLComponents(string: server), parts.scheme?.lowercased() == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.fragment == nil
        else { return false }
        return parts.port.map { (1...65535).contains($0) } ?? true
    }

    static func shellQuote(_ path: String) -> String {
        "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    func arguments(script: String) -> [String] {
        // OpenConnect treats --script as a shell command, so even the fixed trusted path needs quoting.
        let quotedScript = Self.shellQuote(script)
        return buildArguments(scriptCommand: quotedScript, caFile: nil)
    }

    func arguments(
        scriptRunner: String,
        runnerFlag: String = HelperConstants.scriptRunnerFlag,
        caFile: String? = nil
    ) -> [String] {
        let command = "\(Self.shellQuote(scriptRunner)) \(runnerFlag)"
        return buildArguments(scriptCommand: command, caFile: caFile)
    }

    private func buildArguments(scriptCommand: String, caFile: String?) -> [String] {
        var result = [
            "--protocol=\(protocolType)", "--cookie-on-stdin", "--non-inter", "--no-proxy",
            "--no-system-trust",
        ]
        if let caFile, !caFile.isEmpty {
            result.append("--cafile=\(caFile)")
        }
        result.append(contentsOf: [
            "--script=\(scriptCommand)", "--servercert=\(fingerprint)",
        ])
        if let resolve { result.append("--resolve=\(resolve)") }
        return result + ["--", server]
    }
}

enum VPNServiceError: LocalizedError, Equatable {
    case invalidRequest
    case message(String)
    var errorDescription: String? {
        switch self {
        case .invalidRequest: return "Invalid VPN connection parameters."
        case .message(let message): return message
        }
    }
}

/// Incremental byte buffering keeps UTF-8 characters and keywords intact across reads.
struct VPNLineBuffer: Sendable {
    private var pending = Data()
    mutating func append(_ data: Data, final: Bool = false) -> [String] {
        pending.append(data)
        var lines: [String] = []
        while let end = pending.firstIndex(of: 10) {
            lines.append(
                String(decoding: pending[..<end], as: UTF8.self).trimmingCharacters(
                    in: .whitespacesAndNewlines))
            pending.removeSubrange(...end)
        }
        if final && !pending.isEmpty {
            lines.append(
                String(decoding: pending, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
            pending.removeAll()
        }
        // A malformed peer must not cause unbounded memory growth through unterminated lines.
        if pending.count > 1_048_576 {
            pending.removeAll()
            lines.append("[Oversized log line discarded]")
        }
        return lines.filter { !$0.isEmpty }
    }
}

/// Match only the exact one-line rule written by the previous app version.
enum LegacySudoersRule {
    static func matches(_ content: String, username: String) -> Bool {
        ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect", "/usr/bin/openconnect"].contains {
            content == "\(username) ALL=(root) NOPASSWD: \($0), /bin/kill\n"
        }
    }
}

/// Recorded by the fixed network script runner so the supervisor can track and clean up script process groups.
struct VPNScriptLease: Codable, Equatable, Sendable {
    let sessionID: String
    let runnerPID: Int32
    let pgid: Int32
    let parentPID: Int32
    let reason: String
    let startTimeSec: UInt64
}

enum VPNScriptRunner {
    static let sessionIDEnv = "OCGUI_SESSION_ID"
    static let stateDirEnv = "OCGUI_STATE_DIR"
    static let scriptTimeoutEnv = "OCGUI_SCRIPT_TIMEOUT"
    static let parentCheckIntervalEnv = "OCGUI_PARENT_CHECK_MS"

    /// Validates that the runner was invoked with the fixed flag only and no arbitrary script or command arguments.
    static func validateArguments(_ arguments: [String]) -> Bool {
        Array(arguments.dropFirst()) == [HelperConstants.scriptRunnerFlag]
    }

    static func processStartTimeSec(pid: pid_t) -> UInt64? {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.stride
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
        guard ret == Int32(size) else { return nil }
        return info.pbi_start_tvsec
    }

    static func isOwnedProcessAlive(pid: pid_t, expectedPGID: pid_t?, expectedStartTimeSec: UInt64?) -> Bool {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.stride
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
        guard ret == Int32(size), info.pbi_status != SIDL, info.pbi_status != SZOMB else { return false }
        guard info.pbi_uid == getuid() else { return false }
        if let expectedPGID, info.pbi_pgid != UInt32(expectedPGID) { return false }
        if let expectedStartTimeSec, info.pbi_start_tvsec != expectedStartTimeSec { return false }
        return kill(pid, 0) == 0
    }

    /// Executes a fixed vpnc-script inside an isolated process group, recording its session lease,
    /// enforcing a deadline, and monitoring parent OpenConnect liveness.
    static func executeFixedScript(
        scriptURL: URL,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Int32 {
        guard let sessionID = environment[sessionIDEnv], !sessionID.isEmpty,
              let stateDirPath = environment[stateDirEnv], !stateDirPath.isEmpty else {
            fputs("VPNScriptRunner: missing session environment.\n", stderr)
            return 1
        }
        let stateDir = URL(fileURLWithPath: stateDirPath, isDirectory: true)
        let parentPID = getppid()
        let runnerPID = getpid()
        let reason = environment["reason"] ?? "unknown"
        let timeoutSec = environment[scriptTimeoutEnv].flatMap(Double.init) ?? 10.0
        let pollMs = environment[parentCheckIntervalEnv].flatMap(UInt32.init) ?? 50

        let disconnectStartedURL = stateDir.appendingPathComponent("disconnect-started")
        let disconnectCompletedURL = stateDir.appendingPathComponent("disconnect-completed")

        do {
            try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
            if reason == "disconnect" {
                try Data("1".utf8).write(to: disconnectStartedURL, options: .atomic)
            }
        } catch {
            fputs("VPNScriptRunner: cannot prepare state directory: \(error.localizedDescription)\n", stderr)
            return 1
        }

        var fileActions: posix_spawn_file_actions_t?
        var spawnAttr: posix_spawnattr_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawnattr_init(&spawnAttr)
        defer {
            posix_spawn_file_actions_destroy(&fileActions)
            posix_spawnattr_destroy(&spawnAttr)
        }

        // Put vpnc-script in its own dedicated process group (pgid == scriptPID) so killing -scriptPID terminates all script descendants.
        posix_spawnattr_setflags(&spawnAttr, Int16(POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&spawnAttr, 0)

        let argvStrings = [scriptURL.path]
        let cArgs = argvStrings.map { strdup($0) } + [nil]
        let envStrings = environment.map { "\($0.key)=\($0.value)" }
        let cEnv = envStrings.map { strdup($0) } + [nil]
        defer {
            for ptr in cArgs where ptr != nil { free(ptr) }
            for ptr in cEnv where ptr != nil { free(ptr) }
        }

        var scriptPID: pid_t = 0
        let spawnResult = scriptURL.path.withCString { pathPtr in
            posix_spawn(&scriptPID, pathPtr, &fileActions, &spawnAttr, cArgs, cEnv)
        }
        guard spawnResult == 0, scriptPID > 0 else {
            fputs("VPNScriptRunner: posix_spawn failed (\(spawnResult)).\n", stderr)
            return 1
        }

        let pgid = scriptPID
        let startTime = processStartTimeSec(pid: scriptPID) ?? UInt64(Date().timeIntervalSince1970)
        let lease = VPNScriptLease(
            sessionID: sessionID,
            runnerPID: scriptPID,
            pgid: pgid,
            parentPID: runnerPID,
            reason: reason,
            startTimeSec: startTime
        )
        let leaseURL = stateDir.appendingPathComponent("lease-\(scriptPID).json")
        try? JSONEncoder().encode(lease).write(to: leaseURL, options: .atomic)
        defer {
            try? FileManager.default.removeItem(at: leaseURL)
        }

        let deadline = Date().addingTimeInterval(timeoutSec)
        var parentExitedAt: Date?
        var status: Int32 = 0
        var timedOutOrOrphaned = false

        while true {
            var waitStatus: Int32 = 0
            let waited = waitpid(scriptPID, &waitStatus, WNOHANG)
            if waited == scriptPID {
                if (waitStatus & 0x7f) == 0 {
                    status = (waitStatus >> 8) & 0xff
                } else {
                    status = 128 + (waitStatus & 0x7f)
                }
                break
            } else if waited == -1 && errno != EINTR {
                status = 1
                break
            }

            let now = Date()
            if now >= deadline {
                timedOutOrOrphaned = true
                break
            }

            // Monitor parent OpenConnect liveness; if parent died, allow only a short grace window.
            if parentPID <= 1 || kill(parentPID, 0) != 0 {
                if parentExitedAt == nil {
                    parentExitedAt = now
                } else if let exitedAt = parentExitedAt,
                          now.timeIntervalSince(exitedAt) >= min(timeoutSec, reason == "disconnect" ? 1.0 : 0.25) {
                    timedOutOrOrphaned = true
                    break
                }
            }

            usleep(pollMs * 1000)
        }

        if timedOutOrOrphaned {
            kill(-pgid, SIGTERM)
            kill(scriptPID, SIGTERM)
            usleep(150_000)
            var waitStatus: Int32 = 0
            if waitpid(scriptPID, &waitStatus, WNOHANG) == 0 {
                kill(-pgid, SIGKILL)
                kill(scriptPID, SIGKILL)
                _ = waitpid(scriptPID, &waitStatus, 0)
            }
            let timeoutMarker = stateDir.appendingPathComponent("script-forced-termination")
            try? Data("1".utf8).write(to: timeoutMarker, options: .atomic)
            return 124
        }

        if reason == "disconnect" && status == 0 {
            try? Data("1".utf8).write(to: disconnectCompletedURL, options: .atomic)
        }
        return status
    }
}
