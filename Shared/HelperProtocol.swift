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
    static let prepareGatewayFlag = "--prepare-gateway"
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

struct PhysicalDefaultRoute: Equatable, Sendable {
    let interfaceName: String
    let interfaceIndex: UInt32
    let gatewayIPv4: String
}

struct ResolvedGatewayEndpoint: Equatable, Sendable {
    let host: String
    let ip: String
    let isIPv6: Bool
    let rttMs: Double?

    var resolveArgument: String? {
        guard !isIPLiteral(host) else { return nil }
        return "\(host):\(ip)"
    }

    private func isIPLiteral(_ value: String) -> Bool {
        var addr4 = in_addr()
        var addr6 = in6_addr()
        let clean = value.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return inet_pton(AF_INET, clean, &addr4) == 1 || inet_pton(AF_INET6, clean, &addr6) == 1
    }
}

/// Bypasses local TUN Fake-IP DNS interception (e.g. 198.18.0.0/15 from Clash/Surge) by querying DNS
/// and probing TCP latency directly over the physical default-route network interface (IP_BOUND_IF).
enum VPNEndpointResolver {
    static let defaultPublicDNSServers = ["223.5.5.5", "119.29.29.29", "114.114.114.114"]

    /// Returns true if the IPv4 address is a proxy Fake-IP (198.18.0.0/15), loopback, link-local, or unspecified.
    static func isFakeOrUnusableIPv4(_ ip: String) -> Bool {
        var addr = in_addr()
        guard inet_pton(AF_INET, ip, &addr) == 1 else { return true }
        let hostOrder = UInt32(bigEndian: addr.s_addr)
        let b0 = (hostOrder >> 24) & 0xFF
        let b1 = (hostOrder >> 16) & 0xFF
        if b0 == 0 || b0 == 127 || b0 >= 224 { return true }
        if b0 == 169 && b1 == 254 { return true }
        // RFC 2544 benchmark subnet 198.18.0.0/15 is used by Clash / Mihomo / Surge / Sing-box for Fake-IP
        if b0 == 198 && (b1 == 18 || b1 == 19) { return true }
        return false
    }

    static func isValidIPv4(_ ip: String) -> Bool {
        var addr = in_addr()
        return inet_pton(AF_INET, ip, &addr) == 1 && !isFakeOrUnusableIPv4(ip)
    }

    static func isValidIPv6(_ ip: String) -> Bool {
        var addr = in6_addr()
        let clean = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard inet_pton(AF_INET6, clean, &addr) == 1 else { return false }
        let lower = clean.lowercased()
        if lower == "::" || lower == "::1" || lower.hasPrefix("fe80:") || lower.hasPrefix("ff") {
            return false
        }
        return true
    }

    static func physicalDefaultRoute() -> PhysicalDefaultRoute? {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-rn", "-f", "inet"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard let output = String(data: data, encoding: .utf8) else { return nil }
            return parsePhysicalDefaultRoute(from: output)
        } catch {
            return nil
        }
    }

    static func parsePhysicalDefaultRoute(from netstatOutput: String) -> PhysicalDefaultRoute? {
        for rawLine in netstatOutput.components(separatedBy: .newlines) {
            let parts = rawLine.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard parts.count >= 4 else { continue }
            let dest = parts[0]
            let gw = parts[1]
            let netif = parts[3]
            guard dest == "default" || dest == "0.0.0.0" || dest == "0.0.0.0/0" else { continue }
            guard !netif.hasPrefix("utun"), !netif.hasPrefix("lo"), !netif.hasPrefix("gif"), !netif.hasPrefix("stf"),
                  !gw.contains(":"), !gw.hasPrefix("link#"), isValidIPv4(gw) else {
                continue
            }
            let idx = if_nametoindex(netif)
            return PhysicalDefaultRoute(interfaceName: netif, interfaceIndex: idx, gatewayIPv4: gw)
        }
        return nil
    }

    static func buildDNSQuery(host: String, qtype: UInt16, txid: UInt16) -> Data? {
        let labels = host.trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return nil }
        var packet = Data()
        packet.append(UInt8((txid >> 8) & 0xFF))
        packet.append(UInt8(txid & 0xFF))
        packet.append(contentsOf: [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in labels {
            let utf8 = Array(label.utf8)
            guard !utf8.isEmpty && utf8.count <= 63 else { return nil }
            packet.append(UInt8(utf8.count))
            packet.append(contentsOf: utf8)
        }
        packet.append(0x00)
        packet.append(UInt8((qtype >> 8) & 0xFF))
        packet.append(UInt8(qtype & 0xFF))
        packet.append(contentsOf: [0x00, 0x01])
        return packet
    }

    static func parseDNSResponse(_ data: Data, expectedTxid: UInt16, expectedQType: UInt16) -> [String] {
        let bytes = Array(data)
        guard bytes.count >= 12 else { return [] }
        let txid = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let flags = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        guard txid == expectedTxid, (flags & 0x8000) != 0, (flags & 0x000F) == 0 else { return [] }
        let qdcount = Int((UInt16(bytes[4]) << 8) | UInt16(bytes[5]))
        let ancount = Int((UInt16(bytes[6]) << 8) | UInt16(bytes[7]))
        var offset = 12
        for _ in 0..<qdcount {
            guard let afterName = skipDNSName(bytes, from: offset), afterName + 4 <= bytes.count else {
                return []
            }
            offset = afterName + 4
        }
        var results: [String] = []
        for _ in 0..<ancount {
            guard let afterName = skipDNSName(bytes, from: offset), afterName + 10 <= bytes.count else {
                break
            }
            let rtype = (UInt16(bytes[afterName]) << 8) | UInt16(bytes[afterName + 1])
            let rclass = (UInt16(bytes[afterName + 2]) << 8) | UInt16(bytes[afterName + 3])
            let rdlength = Int((UInt16(bytes[afterName + 8]) << 8) | UInt16(bytes[afterName + 9]))
            let rdataStart = afterName + 10
            guard rdataStart + rdlength <= bytes.count else { break }
            if rclass == 1 && rtype == expectedQType {
                if rtype == 1 && rdlength == 4 {
                    var addr = in_addr()
                    withUnsafeMutableBytes(of: &addr.s_addr) { raw in
                        for i in 0..<4 { raw[i] = bytes[rdataStart + i] }
                    }
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                        let ip = String(cString: buf)
                        if isValidIPv4(ip) && !results.contains(ip) {
                            results.append(ip)
                        }
                    }
                } else if rtype == 28 && rdlength == 16 {
                    var addr6 = in6_addr()
                    withUnsafeMutableBytes(of: &addr6) { raw in
                        for i in 0..<16 { raw[i] = bytes[rdataStart + i] }
                    }
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    if inet_ntop(AF_INET6, &addr6, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                        let ip = String(cString: buf)
                        if isValidIPv6(ip) && !results.contains(ip) {
                            results.append(ip)
                        }
                    }
                }
            }
            offset = rdataStart + rdlength
        }
        return results
    }

    private static func skipDNSName(_ bytes: [UInt8], from start: Int) -> Int? {
        var idx = start
        var steps = 0
        while idx < bytes.count && steps < 128 {
            steps += 1
            let len = Int(bytes[idx])
            if len == 0 {
                return idx + 1
            } else if (len & 0xC0) == 0xC0 {
                guard idx + 1 < bytes.count else { return nil }
                return idx + 2
            } else if (len & 0xC0) == 0 {
                idx += 1 + len
            } else {
                return nil
            }
        }
        return nil
    }

    static func queryDNSOverInterface(
        host: String,
        qtype: UInt16,
        dnsServer: String,
        interfaceIndex: UInt32,
        timeoutMs: Int32 = 700
    ) -> [String] {
        let txid = UInt16.random(in: 1...UInt16.max)
        guard let query = buildDNSQuery(host: host, qtype: qtype, txid: txid) else { return [] }
        var serverAddr = sockaddr_in()
        serverAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        serverAddr.sin_family = sa_family_t(AF_INET)
        serverAddr.sin_port = UInt16(53).bigEndian
        guard inet_pton(AF_INET, dnsServer, &serverAddr.sin_addr) == 1 else { return [] }

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [] }
        defer { close(fd) }

        if interfaceIndex > 0 {
            var idx = interfaceIndex
            _ = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
        }

        let sent = query.withUnsafeBytes { rawBuf -> Int in
            withUnsafePointer(to: &serverAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    Darwin.sendto(fd, rawBuf.baseAddress, rawBuf.count, 0, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == query.count else { return [] }

        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard Darwin.poll(&pfd, 1, timeoutMs) > 0, (pfd.revents & Int16(POLLIN)) != 0 else {
            return []
        }

        var responseBuf = [UInt8](repeating: 0, count: 1500)
        let received = Darwin.recv(fd, &responseBuf, responseBuf.count, 0)
        guard received > 0 else { return [] }
        return parseDNSResponse(Data(responseBuf.prefix(received)), expectedTxid: txid, expectedQType: qtype)
    }

    static func measureTCPConnectRTT(
        ip: String,
        port: UInt16,
        isIPv6: Bool,
        interfaceIndex: UInt32,
        timeoutMs: Int32 = 1000
    ) -> Double? {
        let family = isIPv6 ? AF_INET6 : AF_INET
        let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        let flags = fcntl(fd, F_GETFL, 0)
        if flags != -1 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        if interfaceIndex > 0 {
            var idx = interfaceIndex
            if isIPv6 {
                _ = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
            } else {
                _ = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
            }
        }

        let startNs = DispatchTime.now().uptimeNanoseconds
        let connectResult: Int32
        if isIPv6 {
            var addr6 = sockaddr_in6()
            addr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr6.sin6_family = sa_family_t(AF_INET6)
            addr6.sin6_port = port.bigEndian
            let clean = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            guard inet_pton(AF_INET6, clean, &addr6.sin6_addr) == 1 else { return nil }
            connectResult = withUnsafePointer(to: &addr6) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            var addr4 = sockaddr_in()
            addr4.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr4.sin_family = sa_family_t(AF_INET)
            addr4.sin_port = port.bigEndian
            guard inet_pton(AF_INET, ip, &addr4.sin_addr) == 1 else { return nil }
            connectResult = withUnsafePointer(to: &addr4) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        if connectResult == 0 {
            let elapsedNs = DispatchTime.now().uptimeNanoseconds - startNs
            return Double(elapsedNs) / 1_000_000.0
        }
        guard errno == EINPROGRESS else { return nil }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard Darwin.poll(&pfd, 1, timeoutMs) > 0, (pfd.revents & Int16(POLLOUT)) != 0 else {
            return nil
        }
        var soError: Int32 = 0
        var errLen = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &errLen) == 0, soError == 0 else {
            return nil
        }
        let elapsedNs = DispatchTime.now().uptimeNanoseconds - startNs
        return Double(elapsedNs) / 1_000_000.0
    }

    static func configuredDNSServers() -> [String] {
        var servers: [String] = []
        if let resolv = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) {
            for line in resolv.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.hasPrefix("nameserver") else { continue }
                let parts = trimmed.split(whereSeparator: { $0.isWhitespace }).map(String.init)
                if parts.count >= 2, isValidIPv4(parts[1]), !servers.contains(parts[1]) {
                    servers.append(parts[1])
                }
            }
        }
        for fallback in defaultPublicDNSServers where !servers.contains(fallback) {
            servers.append(fallback)
        }
        return servers
    }

    static func systemResolvedAddresses(host: String) -> (ipv4: [String], ipv6: [String]) {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else {
            return ([], [])
        }
        defer { freeaddrinfo(first) }
        var v4: [String] = []
        var v6: [String] = []
        var ptr: UnsafeMutablePointer<addrinfo>? = first
        while let info = ptr?.pointee {
            if info.ai_family == AF_INET, let sa = info.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var addr = sin.pointee.sin_addr
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                        let ip = String(cString: buf)
                        if isValidIPv4(ip) && !v4.contains(ip) { v4.append(ip) }
                    }
                }
            } else if info.ai_family == AF_INET6, let sa = info.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    var addr = sin6.pointee.sin6_addr
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    if inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                        let ip = String(cString: buf)
                        if isValidIPv6(ip) && !v6.contains(ip) { v6.append(ip) }
                    }
                }
            }
            ptr = info.ai_next
        }
        return (v4, v6)
    }

    /// Resolves non-Fake-IP addresses for the VPN gateway over the physical interface and selects the lowest-latency endpoint.
    static func resolveBestEndpoint(for normalizedServer: String) -> ResolvedGatewayEndpoint? {
        guard let components = URLComponents(string: normalizedServer),
              let rawHost = components.host, !rawHost.isEmpty else {
            return nil
        }
        let host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let port = UInt16(components.port ?? 443)
        let route = physicalDefaultRoute()
        let ifIndex = route?.interfaceIndex ?? 0

        if isValidIPv4(host) {
            let rtt = measureTCPConnectRTT(ip: host, port: port, isIPv6: false, interfaceIndex: ifIndex)
            return ResolvedGatewayEndpoint(host: host, ip: host, isIPv6: false, rttMs: rtt)
        }
        if isValidIPv6(host) {
            let rtt = measureTCPConnectRTT(ip: host, port: port, isIPv6: true, interfaceIndex: ifIndex)
            return ResolvedGatewayEndpoint(host: host, ip: host, isIPv6: true, rttMs: rtt)
        }

        var ipv4Candidates: [String] = []
        var ipv6Candidates: [String] = []

        if ifIndex > 0 {
            for dns in configuredDNSServers() {
                let aRecords = queryDNSOverInterface(host: host, qtype: 1, dnsServer: dns, interfaceIndex: ifIndex)
                let aaaaRecords = queryDNSOverInterface(host: host, qtype: 28, dnsServer: dns, interfaceIndex: ifIndex)
                for ip in aRecords where !ipv4Candidates.contains(ip) { ipv4Candidates.append(ip) }
                for ip in aaaaRecords where !ipv6Candidates.contains(ip) { ipv6Candidates.append(ip) }
                if !ipv4Candidates.isEmpty { break }
            }
        }

        let sys = systemResolvedAddresses(host: host)
        for ip in sys.ipv4 where !ipv4Candidates.contains(ip) { ipv4Candidates.append(ip) }
        for ip in sys.ipv6 where !ipv6Candidates.contains(ip) { ipv6Candidates.append(ip) }

        guard !ipv4Candidates.isEmpty || !ipv6Candidates.isEmpty else { return nil }

        struct ScoredCandidate {
            let endpoint: ResolvedGatewayEndpoint
            let score: Double
        }

        let lock = NSLock()
        var scored: [ScoredCandidate] = []
        let group = DispatchGroup()

        let allCandidates: [(ip: String, isIPv6: Bool)] =
            ipv4Candidates.prefix(3).map { ($0, false) } +
            ipv6Candidates.prefix(2).map { ($0, true) }

        for candidate in allCandidates {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                let rtt1 = measureTCPConnectRTT(ip: candidate.ip, port: port, isIPv6: candidate.isIPv6, interfaceIndex: ifIndex)
                let rtt2: Double?
                if rtt1 != nil {
                    usleep(20_000)
                    rtt2 = measureTCPConnectRTT(ip: candidate.ip, port: port, isIPv6: candidate.isIPv6, interfaceIndex: ifIndex)
                } else {
                    rtt2 = nil
                }
                if let bestRTT = [rtt1, rtt2].compactMap({ $0 }).min() {
                    // Prefer IPv4 when latency is similar due to smaller header overhead and broader DTLS support
                    let score = candidate.isIPv6 ? (bestRTT + 5.0) : bestRTT
                    let ep = ResolvedGatewayEndpoint(host: host, ip: candidate.ip, isIPv6: candidate.isIPv6, rttMs: bestRTT)
                    lock.lock()
                    scored.append(ScoredCandidate(endpoint: ep, score: score))
                    lock.unlock()
                }
            }
        }
        _ = group.wait(timeout: .now() + 2.2)

        if let winner = scored.min(by: { $0.score < $1.score }) {
            return winner.endpoint
        }
        if let firstV4 = ipv4Candidates.first {
            return ResolvedGatewayEndpoint(host: host, ip: firstV4, isIPv6: false, rttMs: nil)
        }
        if let firstV6 = ipv6Candidates.first {
            return ResolvedGatewayEndpoint(host: host, ip: firstV6, isIPv6: true, rttMs: nil)
        }
        return nil
    }

    static func splitResolve(_ resolve: String) -> (host: String, ip: String)? {
        guard let colon = resolve.firstIndex(of: ":") else { return nil }
        let host = String(resolve[..<colon])
        let ip = String(resolve[resolve.index(after: colon)...])
        guard !host.isEmpty && !ip.isEmpty else { return nil }
        return (host, ip)
    }

    /// Selects the best `--resolve=host:ip` value, replacing Fake-IPs or slower fallback routes when a verified preferred endpoint matches the target host.
    static func selectResolve(
        authResolve: String?,
        preferredResolve: String?,
        targetServer: String
    ) -> String? {
        let targetHost = URLComponents(string: TunnelRequest.normalizeServer(targetServer))?.host?
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()

        if let preferredResolve,
           let prefParts = splitResolve(preferredResolve),
           prefParts.host.lowercased() == targetHost {
            if let authResolve, let authParts = splitResolve(authResolve) {
                if authParts.host.lowercased() != prefParts.host.lowercased() && !isFakeOrUnusableIPv4(authParts.ip) {
                    return authResolve
                }
            }
            return preferredResolve
        }

        if let authResolve, let authParts = splitResolve(authResolve) {
            if !authParts.ip.contains(":") && isFakeOrUnusableIPv4(authParts.ip) {
                return nil
            }
            return authResolve
        }
        return preferredResolve
    }

    static func extractGatewayIP(from request: TunnelRequest) -> String? {
        if let resolve = request.resolve, let parts = splitResolve(resolve) {
            if isValidIPv4(parts.ip) || isValidIPv6(parts.ip) {
                return parts.ip
            }
        }
        if let host = URLComponents(string: request.server)?.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")) {
            if isValidIPv4(host) || isValidIPv6(host) {
                return host
            }
        }
        return nil
    }

    /// Installs a direct /32 host route for an IPv4 VPN gateway via the physical default gateway (e.g. en0)
    /// so TUN proxies using split routes (1/8, 2/7, ..., 128/1 -> utun) cannot hijack the VPN tunnel itself.
    @discardableResult
    static func installDirectGatewayRoute(ip: String) -> Bool {
        guard isValidIPv4(ip), let route = physicalDefaultRoute() else { return false }
        let runRoute = { (args: [String]) -> Int32 in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/sbin/route")
            task.arguments = args
            task.standardOutput = FileHandle.nullDevice
            task.standardError = FileHandle.nullDevice
            do {
                try task.run()
                task.waitUntilExit()
                return task.terminationStatus
            } catch {
                return -1
            }
        }
        _ = runRoute(["-n", "delete", "-host", ip])
        return runRoute(["-n", "add", "-host", ip, route.gatewayIPv4]) == 0
    }
}
