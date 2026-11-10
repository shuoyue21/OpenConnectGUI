import Foundation

/// Parses OpenConnect's --authenticate output as data. It is never passed to a shell/eval.
struct AuthenticationResult {
    let fields: [String: String]

    init(data: Data) throws {
        guard data.count <= 262144, let text = String(data: data, encoding: .utf8) else { throw VPNServiceError.invalidRequest }
        var fields: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) where !line.isEmpty {
            guard let equal = line.firstIndex(of: "=") else { continue }
            let name = String(line[..<equal])
            guard ["COOKIE", "HOST", "CONNECT_URL", "FINGERPRINT", "RESOLVE"].contains(name) else { continue }
            guard fields[name] == nil else { throw VPNServiceError.invalidRequest }
            let value = String(line[line.index(after: equal)...])
            fields[name] = name == "RESOLVE" && value.isEmpty ? "" : try Self.unquote(value)
        }
        self.fields = fields
    }

    func request(protocolType: String, originalServer: String) throws -> TunnelRequest {
        let server = fields["CONNECT_URL"] ?? fields["HOST"] ?? originalServer
        let request = TunnelRequest(
            server: TunnelRequest.normalizeServer(server),
            protocolType: protocolType,
            cookie: fields["COOKIE"] ?? "",
            fingerprint: fields["FINGERPRINT"] ?? "",
            resolve: fields["RESOLVE"].flatMap { $0.isEmpty ? nil : $0 }
        )
        try request.validate()
        return request
    }

    static func unquote(_ input: String) throws -> String {
        // OpenConnect 9.21 prints raw values between single quotes (not shell-escaped
        // strings). Embedded apostrophes are data; never interpret substitutions or escapes.
        guard input.count >= 2, input.first == "'", input.last == "'",
              !input.contains(where: { $0.isNewline || $0 == "\0" }) else {
            throw VPNServiceError.invalidRequest
        }
        return String(input.dropFirst().dropLast())
    }
}

enum VPNFailureKind: Equatable, Sendable {
    case userCancelled
    case credentialsRejected(String)
    case accountLocked(String)
    case certificateError(String)
    case transientNetworkError(String)
    case localServiceError(String)
    case unclassified(String)

    var allowsAutomaticRetry: Bool {
        if case .transientNetworkError = self { return true }
        return false
    }

    var message: String? {
        switch self {
        case .userCancelled:
            return nil
        case .credentialsRejected(let msg),
             .accountLocked(let msg),
             .certificateError(let msg),
             .transientNetworkError(let msg),
             .localServiceError(let msg),
             .unclassified(let msg):
            return msg
        }
    }
}

/// Unified failure classifier across all supported OpenConnect protocols and execution stages.
enum VPNFailureClassifier {
    private static let genericSummaryFragments: [String] = [
        "failed to complete authentication",
        "failed to obtain webvpn cookie"
    ]

    private static let accountLockedFragments: [String] = [
        "account locked",
        "account is locked",
        "account has been locked",
        "user account locked",
        "user is locked",
        "account disabled",
        "too many failed",
        "maximum number of failed",
        "locked out",
        "temporarily locked",
        "account is currently locked",
        "locked due to"
    ]

    private static let certificateErrorFragments: [String] = [
        "server certificate verify failed",
        "certificate verification failed",
        "failed verification",
        "certificate didn't match",
        "certificate does not match",
        "certificate has expired",
        "certificate is not trusted",
        "certificate issuer is not known",
        "signer not found",
        "client certificate",
        "certificate is required",
        "certificate required",
        "certificate auth failed",
        "certificate authentication failed",
        "certificate rejected",
        "failed to load client certificate",
        "no client certificate",
        "ssl certificate authentication failed",
        "peer certificate"
    ]

    private static let credentialsRejectedFragments: [String] = [
        "login failed",
        "authentication failed",
        "auth failed",
        "password is incorrect",
        "invalid username or password",
        "invalid user or password",
        "bad username or password",
        "invalid credentials",
        "wrong password",
        "invalid login",
        "access denied: invalid",
        "username or password is invalid",
        "check your username and password",
        "session authentication failed",
        "authentication rejected",
        "authentication failure:",
        "password expired"
    ]

    private static let transientNetworkFragments: [String] = [
        "creating ssl connection failed",
        "ssl connection failure",
        "ssl handshake failed",
        "tls handshake failed",
        "failed to open https connection",
        "failed to connect to",
        "failed to reconnect",
        "connection timed out",
        "operation timed out",
        "network is unreachable",
        "network is down",
        "host is down",
        "no route to host",
        "can't assign requested address",
        "cannot assign requested address",
        "connection refused",
        "connection reset by peer",
        "connection aborted",
        "software caused connection abort",
        "broken pipe",
        "socket is not connected",
        "getaddrinfo failed",
        "temporary failure in name resolution",
        "nodename nor servname provided",
        "could not resolve",
        "ssl read error",
        "tls read error",
        "failed to write to ssl",
        "failed to read from ssl",
        "gnutls recv error",
        "unexpected eof",
        "dtls handshake timed out",
        "esp session timed out",
        "dead peer detected",
        "keepalive timed out",
        "cstp dead peer detection",
        "cstp rekey due",
        "reconnect gave different",
        "cookie is no longer valid",
        "reconnect failed",
        "session terminated by",
        "session expired",
        "session has expired",
        "cookie was rejected",
        "server disconnected",
        "eof on",
        "recv failed",
        "send failed"
    ]

    static func classify(
        protocolType: String,
        stage: VPNExecutionStage,
        outcome: VPNExitOutcome,
        wasConnected: Bool,
        userCancelled: Bool,
        explicitFailure: String?,
        logs: [String]
    ) -> VPNFailureKind {
        if !outcome.processConfirmedStopped {
            return .localServiceError("VPN process did not confirm termination. Check the background service before retrying.")
        }
        if !outcome.networkCleanupComplete || outcome.wasForceKilled {
            return .localServiceError("VPN process required forced termination; DNS or routing cleanup may not have completed.")
        }
        if userCancelled {
            return .userCancelled
        }
        if let explicitFailure, !explicitFailure.isEmpty {
            return .localServiceError(explicitFailure)
        }
        if stage == .setup {
            return .localServiceError("VPN background service setup did not complete.")
        }

        let meaningfulLines = logs
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { line in
                !line.isEmpty && !genericSummaryFragments.contains(where: { line == $0 || line.hasPrefix($0) })
            }

        for line in meaningfulLines {
            if accountLockedFragments.contains(where: { line.contains($0) }) {
                return .accountLocked("Account is locked on the \(protocolType) gateway. Unlock your account, then connect manually.")
            }
        }

        if !(wasConnected && stage == .tunneling) {
            let lastHTTPSConnectIndex = meaningfulLines.lastIndex(where: { $0.contains("connected to https on") })
            for (index, line) in meaningfulLines.enumerated() {
                if stage == .tunneling,
                   let lastHTTPSConnectIndex,
                   index < lastHTTPSConnectIndex,
                   (line.contains("server certificate verify failed") || line.contains("signer not found")) {
                    // Superseded by --servercert pin verification ("Connected to HTTPS on ...").
                    continue
                }
                if certificateErrorFragments.contains(where: { line.contains($0) }) {
                    return .certificateError("Certificate validation or client certificate error for \(protocolType). Verify certificate settings and retry manually.")
                }
            }

            for line in meaningfulLines {
                if credentialsRejectedFragments.contains(where: { line.contains($0) }) {
                    return .credentialsRejected("Authentication failed. Verify or update your credentials to retry.")
                }
            }
        }

        for line in meaningfulLines {
            if transientNetworkFragments.contains(where: { line.contains($0) }) {
                return .transientNetworkError("Temporary network error (\(protocolType), status \(outcome.status)).")
            }
        }

        if wasConnected && stage == .tunneling {
            return .transientNetworkError("Connection ended unexpectedly (status \(outcome.status)).")
        }

        return .unclassified("Connection ended with an unclassified error (stage: \(stage.rawValue), status: \(outcome.status)). Review logs and retry manually.")
    }

    /// Parses available group labels when OpenConnect exits in non-interactive mode at a `GROUP: [g1|g2|...]:` prompt.
    static func extractAuthGroupChoices(from logs: [String]) -> [String]? {
        let requiresInput = logs.contains {
            $0.localizedCaseInsensitiveContains("User input required in non-interactive mode")
        }
        guard requiresInput else { return nil }
        for line in logs.reversed() {
            guard let openBracket = line.range(of: " ["),
                  let closeBracket = line.range(of: "]:", options: .backwards),
                  openBracket.upperBound < closeBracket.lowerBound else {
                continue
            }
            let rawChoices = line[openBracket.upperBound..<closeBracket.lowerBound]
            let choices = rawChoices
                .split(separator: "|", omittingEmptySubsequences: false)
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if !choices.isEmpty {
                return choices
            }
        }
        return nil
    }
}
