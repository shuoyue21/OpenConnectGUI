import Foundation
import AppKit
import Combine
import Network

@MainActor
final class VPNConnectionState: ObservableObject, Identifiable {
    enum Phase: Equatable {
        case idle
        case authorizing
        case connecting
        case connected
        case waitingForNetwork
        case recoveringConnection
        case reconnecting
        case disconnecting
        case needsCredentials
        case accountLocked(String)
        case failed(String)
    }

    enum ProcessLifecycle: Equatable {
        case stopped
        case authorizing
        case connecting
        case running
        case stopping
    }

    enum TunnelRecoveryState: Equatable {
        case none
        case established
        case waitingForNetwork
        case recovering
        case recoveryTimedOut
    }

    private enum SessionStopReason: Equatable {
        case userDisconnect
        case applyConfigurationChanges(String?)
        case recoveryTimeoutAutoReconnect
        case recoveryTimeoutManualRequired
        case systemSleep
    }

    private struct Session {
        let id: UUID
        let config: VPNConfiguration
        var stage: VPNExecutionStage = .authenticating
        var buffer = VPNLineBuffer()
        var sessionLogs: [String] = []
        var wasConnected = false
        var tunnelRecovery: TunnelRecoveryState = .none
        var stopReason: SessionStopReason?
        var unconfirmedStop = false
    }

    let id: UUID
    private(set) var config: VPNConfiguration
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var processLifecycle: ProcessLifecycle = .stopped
    @Published private(set) var tunnelRecoveryState: TunnelRecoveryState = .none
    @Published private(set) var isNetworkAvailable: Bool = true
    @Published private(set) var logs: [String] = []
    @Published var isPendingDeletion: Bool = false
    @Published private(set) var availableGroups: [String] = []
    @Published var isSelectingGroup: Bool = false

    /// Read-only snapshot of the configuration used by the currently active session.
    var activeConfiguration: VPNConfiguration? { activeSession?.config }

    /// True when server, username, protocol, or authGroup was edited while a session is active.
    var hasPendingConfigurationChanges: Bool {
        guard let active = activeConfiguration else { return false }
        return !active.hasSameIdentity(as: config) || active.trimmedAuthGroup != config.trimmedAuthGroup
    }

    var isConnected: Bool { phase == .connected }
    var isConnecting: Bool { phase == .authorizing || phase == .connecting }
    var isReconnecting: Bool { phase == .reconnecting }
    var isWaitingForNetwork: Bool { phase == .waitingForNetwork }
    var isRecoveringConnection: Bool { phase == .recoveringConnection }
    var isDisconnecting: Bool { phase == .disconnecting }
    var canConnect: Bool { activeSession == nil && !isDisconnecting && !isPendingDeletion }
    var hasUnfinishedProcess: Bool { activeSession != nil || isDisconnecting }
    var needsCredentials: Bool { phase == .needsCredentials }
    var isAccountLocked: Bool {
        if case .accountLocked = phase { return true }
        return false
    }

    private var activeSession: Session?
    private let transport: VPNTransport
    private let loadPassword: (VPNConfiguration) -> String?
    private let notify: (Bool, String) -> Void
    private let retryDelay: (Int) -> TimeInterval
    private let recoveryTimeout: TimeInterval
    private var reconnectTask: Task<Void, Never>?
    private var reconnectGeneration = UUID()
    private var recoveryTask: Task<Void, Never>?
    private var recoveryGeneration = UUID()
    private var reconnectAttempt = 0
    private var wantsConnection = false
    private var isSystemSleeping = false
    private var isDisplayAsleep = false
    private var pendingWakeReconnect = false
    private var cachedPassword: String?
    private var authenticationBlocked = false
    private var accountLockedMessage: String?
    private var retryBlockedByFailure = false
    private var pathMonitor: NWPathMonitor?
    private var sleepObserver: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    private var screenSleepObserver: NSObjectProtocol?
    private var screenWakeObserver: NSObjectProtocol?
    private var backgroundActivityToken: NSObjectProtocol?
    private var monitorGeneration = UUID()
    private let monitorsNetwork: Bool
    private var disconnectCallbacks: [(Bool) -> Void] = []

    init(
        config: VPNConfiguration,
        transport: VPNTransport? = nil,
        monitorsNetwork: Bool = true,
        recoveryTimeout: TimeInterval = 15.0,
        loadPassword: @escaping (VPNConfiguration) -> String? = KeychainService.loadPassword,
        retryDelay: @escaping (Int) -> TimeInterval = { min(pow(2, Double(min($0, 4))) * 2, 30) },
        notify: @escaping (Bool, String) -> Void = { connected, name in
            if connected { NotificationManager.postConnectionSuccess(for: name) }
            else { NotificationManager.postConnectionDisconnected(for: name) }
        }
    ) {
        self.id = config.id
        self.config = config
        self.transport = transport ?? HelperVPNTransport()
        self.monitorsNetwork = monitorsNetwork
        self.recoveryTimeout = recoveryTimeout
        self.loadPassword = loadPassword
        self.retryDelay = retryDelay
        self.notify = notify
    }

    deinit {
        reconnectTask?.cancel()
        recoveryTask?.cancel()
        pathMonitor?.cancel()
        if let backgroundActivityToken {
            ProcessInfo.processInfo.endActivity(backgroundActivityToken)
        }
        if let sleepObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(sleepObserver)
        }
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
        if let screenSleepObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(screenSleepObserver)
        }
        if let screenWakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(screenWakeObserver)
        }
    }

    private var canAutoReconnect: Bool {
        wantsConnection &&
        (config.autoReconnect || pendingWakeReconnect) &&
        !authenticationBlocked &&
        accountLockedMessage == nil &&
        !retryBlockedByFailure &&
        !hasPendingConfigurationChanges &&
        activeSession == nil &&
        phase != .disconnecting &&
        !isPendingDeletion
    }

    func updateConfig(_ updated: VPNConfiguration) {
        let identityChangedFromNext = !config.hasSameIdentity(as: updated)
        let identityDiffersFromActive = activeSession.map { !$0.config.hasSameIdentity(as: updated) } ?? false
        config = updated
        if identityChangedFromNext || identityDiffersFromActive {
            // Active session keeps its immutable configuration snapshot. Never reuse its password for a new target.
            cachedPassword = nil
            wantsConnection = false
            pendingWakeReconnect = false
            authenticationBlocked = true
            cancelPendingReconnect()
            if activeSession == nil {
                phase = .needsCredentials
                stopNetworkMonitor()
            }
        } else if !updated.autoReconnect {
            pendingWakeReconnect = false
            cancelPendingReconnect()
            if activeSession == nil && (phase == .reconnecting || phase == .waitingForNetwork) {
                wantsConnection = false
                phase = .idle
                stopNetworkMonitor()
            }
        }
    }

    func credentialsChanged(_ password: String?) {
        cachedPassword = password
        // Updating a password resolves credential rejection, but never bypasses an account lockout.
        guard accountLockedMessage == nil else { return }
        if let password, !password.isEmpty {
            authenticationBlocked = false
            retryBlockedByFailure = false
            if phase == .needsCredentials { phase = .idle }
            if canAutoReconnect { scheduleReconnect() }
        } else if !(config.rememberCredentials && loadPassword(config) != nil) {
            if activeSession == nil && (phase == .reconnecting || phase == .waitingForNetwork) {
                cancelPendingReconnect()
                phase = .needsCredentials
            }
        }
    }

    func connect(with password: String) {
        guard canConnect else { return }
        guard !password.isEmpty, !password.contains(where: { $0.isNewline || $0 == "\0" }) else {
            phase = .needsCredentials
            log("Enter a valid VPN password.")
            return
        }
        wantsConnection = true
        isSystemSleeping = false
        pendingWakeReconnect = false
        authenticationBlocked = false
        accountLockedMessage = nil
        retryBlockedByFailure = false
        isSelectingGroup = false
        cachedPassword = password
        reconnectAttempt = 0
        beginSession(password: password)
    }

    func connectWithSelectedGroup(_ group: String, updatedConfig: VPNConfiguration, fallbackPassword: String? = nil) {
        isSelectingGroup = false
        config = updatedConfig
        let passwordToUse = cachedPassword ?? fallbackPassword ?? (config.rememberCredentials ? loadPassword(config) : nil)
        if let passwordToUse, !passwordToUse.isEmpty {
            connect(with: passwordToUse)
        } else {
            phase = .needsCredentials
            log("Enter your VPN password to connect with group '\(group)'.")
        }
    }

    /// Stops the active session first, waits for confirmed stop, then connects using the updated configuration.
    func reconnectToApplyChanges(with explicitPassword: String? = nil) {
        guard !isPendingDeletion else { return }
        let resolvedPassword = explicitPassword.flatMap { $0.isEmpty ? nil : $0 }
        if let session = activeSession {
            guard phase != .disconnecting else { return }
            wantsConnection = false
            pendingWakeReconnect = false
            cancelPendingReconnect()
            cancelRecoveryTimer()
            var updatedSession = session
            updatedSession.stopReason = .applyConfigurationChanges(resolvedPassword)
            activeSession = updatedSession
            processLifecycle = .stopping
            phase = .disconnecting
            log("Stopping connection to \(session.config.serverAddress) before applying changes...")
            transport.stop(session: session.id)
        } else {
            let nextPassword = resolvedPassword ?? (config.rememberCredentials ? loadPassword(config) : nil)
            if let nextPassword, !nextPassword.isEmpty {
                connect(with: nextPassword)
            } else {
                authenticationBlocked = true
                cachedPassword = nil
                phase = .needsCredentials
                log("Enter credentials for \(config.serverAddress) to apply the updated configuration.")
            }
        }
    }

    private func beginSession(password: String) {
        guard activeSession == nil else { return }
        cancelPendingReconnect()
        cancelRecoveryTimer()
        let session = Session(id: UUID(), config: config)
        activeSession = session
        processLifecycle = .authorizing
        tunnelRecoveryState = .none
        phase = .authorizing
        startNetworkMonitor()
        log("Connecting to \(session.config.serverAddress)...")
        transport.start(session: session.id, config: session.config, password: password) { [weak self] event in
            self?.receive(event, sessionID: session.id)
        }
    }

    func disconnect(completion: ((Bool) -> Void)? = nil) {
        if let completion {
            disconnectCallbacks.append(completion)
        }
        wantsConnection = false
        isSystemSleeping = false
        pendingWakeReconnect = false
        cachedPassword = nil
        authenticationBlocked = false
        cancelPendingReconnect()
        cancelRecoveryTimer()
        stopNetworkMonitor()
        guard var session = activeSession else {
            processLifecycle = .stopped
            tunnelRecoveryState = .none
            if phase != .idle { phase = .idle }
            completeDisconnectCallbacks(true)
            return
        }
        let alreadyDisconnecting = (phase == .disconnecting && !session.unconfirmedStop)
        session.unconfirmedStop = false
        session.stopReason = .userDisconnect
        activeSession = session
        processLifecycle = .stopping
        phase = .disconnecting
        guard !alreadyDisconnecting else { return }
        transport.stop(session: session.id)
    }

    private func completeDisconnectCallbacks(_ success: Bool) {
        guard !disconnectCallbacks.isEmpty else { return }
        let callbacks = disconnectCallbacks
        disconnectCallbacks.removeAll()
        callbacks.forEach { $0(success) }
    }

    private func receive(_ event: VPNTransportEvent, sessionID: UUID) {
        guard activeSession?.id == sessionID else { return }
        switch event {
        case .connecting:
            activeSession?.stage = .authenticating
            if phase != .disconnecting {
                processLifecycle = .connecting
                phase = .connecting
            }
        case .tunnelStarting:
            activeSession?.stage = .tunneling
            if phase != .disconnecting {
                processLifecycle = .connecting
                phase = .connecting
            }
        case .output(let data):
            consume(data)
        case .ended(let outcome):
            finish(outcome: outcome, explicitFailure: nil)
        case .failed(let message):
            let stage: VPNExecutionStage = (processLifecycle == .authorizing) ? .setup : (activeSession?.stage ?? .setup)
            activeSession?.stage = stage
            finish(outcome: VPNExitOutcome(status: -1), explicitFailure: message)
        }
    }

    private static func isTunnelEstablishedLine(_ line: String) -> Bool {
        line.contains("Configured as ") ||
        line.contains("Connected as ") ||
        line.contains("Established DTLS connection") ||
        line.contains("ESP session established") ||
        line.contains("DTLS tunnel connected") ||
        line.contains("Session resumed")
    }

    private func consume(_ data: Data, final: Bool = false) {
        guard var session = activeSession else { return }
        let lines = session.buffer.append(data, final: final)
        for line in lines {
            session.sessionLogs.append(line)
            if phase != .disconnecting, session.stopReason == nil, Self.isTunnelEstablishedLine(line) {
                let firstConnection = !session.wasConnected
                session.wasConnected = true
                session.stage = .tunneling
                processLifecycle = .running
                pendingWakeReconnect = false
                reconnectAttempt = 0
                cancelRecoveryTimer()
                if isNetworkAvailable {
                    session.tunnelRecovery = .established
                    tunnelRecoveryState = .established
                    phase = .connected
                } else {
                    session.tunnelRecovery = .waitingForNetwork
                    tunnelRecoveryState = .waitingForNetwork
                    phase = .waitingForNetwork
                }
                if firstConnection {
                    notify(true, session.config.name)
                    log("Connected to \(session.config.serverAddress)")
                } else {
                    log("Tunnel recovery confirmed for \(session.config.serverAddress)")
                }
            }
            log(line)
        }
        activeSession = session
    }

    private func finish(outcome: VPNExitOutcome, explicitFailure: String?) {
        consume(Data(), final: true)
        cancelRecoveryTimer()
        guard var session = activeSession else { return }

        if !outcome.logsComplete {
            log("Log stream did not close cleanly before timeout; some trailing log lines may be missing.")
        }

        // Never discard a session unless the main process is confirmed stopped.
        guard outcome.processConfirmedStopped else {
            session.unconfirmedStop = true
            activeSession = session
            processLifecycle = .running
            let message = "VPN process did not confirm termination. Connection controls remain active so you can retry disconnecting."
            phase = .failed(message)
            retryBlockedByFailure = true
            log(message)
            completeDisconnectCallbacks(false)
            return
        }

        let stopReason = session.stopReason
        activeSession = nil
        processLifecycle = .stopped
        if session.wasConnected {
            notify(false, session.config.name)
        }

        switch stopReason {
        case .userDisconnect:
            tunnelRecoveryState = .none
            if outcome.cleanTermination {
                phase = .idle
                log("Disconnected.")
                completeDisconnectCallbacks(true)
            } else {
                let message = "VPN process was forcibly terminated; DNS or routing cleanup may not have completed."
                phase = .failed(message)
                retryBlockedByFailure = true
                log(message)
                completeDisconnectCallbacks(false)
            }
            return

        case .applyConfigurationChanges(let explicitNextPassword):
            tunnelRecoveryState = .none
            guard outcome.cleanTermination else {
                let message = "Previous VPN session did not clean up cleanly; aborted switching to the new configuration."
                phase = .failed(message)
                retryBlockedByFailure = true
                stopNetworkMonitor()
                log(message)
                completeDisconnectCallbacks(false)
                return
            }
            completeDisconnectCallbacks(true)
            let nextPassword = explicitNextPassword ?? (config.rememberCredentials ? loadPassword(config) : nil)
            if let nextPassword, !nextPassword.isEmpty {
                connect(with: nextPassword)
            } else {
                authenticationBlocked = true
                cachedPassword = nil
                phase = .needsCredentials
                stopNetworkMonitor()
                log("Enter credentials for \(config.serverAddress) to connect with the updated configuration.")
            }
            return

        case .recoveryTimeoutAutoReconnect:
            if !outcome.cleanTermination {
                log("Stale VPN session required forced termination after recovery timeout; proceeding with automatic reconnect...")
            }
            tunnelRecoveryState = .none
            phase = .reconnecting
            completeDisconnectCallbacks(true)
            log("Previous session stopped after recovery timeout. Starting a fresh connection...")
            scheduleReconnect()
            return

        case .recoveryTimeoutManualRequired:
            tunnelRecoveryState = .recoveryTimedOut
            let message = "Connection did not recover after network restore. Please reconnect manually."
            phase = .failed(message)
            retryBlockedByFailure = true
            wantsConnection = false
            pendingWakeReconnect = false
            cachedPassword = nil
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(outcome.cleanTermination)
            return

        case .systemSleep:
            if !outcome.cleanTermination {
                log("Previous VPN session required forced termination during sleep transition; proceeding with wake recovery.")
            }
            completeDisconnectCallbacks(true)
            if isSystemSleeping {
                tunnelRecoveryState = .waitingForNetwork
                phase = .waitingForNetwork
                log("VPN session suspended for system sleep. Will reconnect upon wake...")
            } else if canAutoReconnect {
                tunnelRecoveryState = .none
                phase = .reconnecting
                log("System woke from sleep. Starting a fresh VPN connection...")
                scheduleReconnect()
            } else {
                tunnelRecoveryState = .none
                phase = .idle
                wantsConnection = false
                pendingWakeReconnect = false
                cachedPassword = nil
                stopNetworkMonitor()
            }
            return

        case .none:
            break
        }

        if !wantsConnection && explicitFailure == nil && outcome.cleanTermination {
            tunnelRecoveryState = .none
            phase = .idle
            log("Disconnected.")
            completeDisconnectCallbacks(true)
            return
        }

        if session.stage == .authenticating,
           explicitFailure == nil,
           let groups = VPNFailureClassifier.extractAuthGroupChoices(from: session.sessionLogs),
           !groups.isEmpty {
            tunnelRecoveryState = .none
            availableGroups = groups
            isSelectingGroup = true
            retryBlockedByFailure = true
            wantsConnection = false
            pendingWakeReconnect = false
            let message = "Select a VPN group (\(groups.joined(separator: " / "))) to connect."
            phase = .failed(message)
            cancelPendingReconnect()
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(outcome.cleanTermination)
            return
        }

        let classification = VPNFailureClassifier.classify(
            protocolType: session.config.effectiveProtocol,
            stage: session.stage,
            outcome: outcome,
            wasConnected: session.wasConnected,
            userCancelled: false,
            explicitFailure: explicitFailure,
            logs: session.sessionLogs
        )

        tunnelRecoveryState = .none
        switch classification {
        case .userCancelled:
            phase = .idle
            wantsConnection = false
            pendingWakeReconnect = false
            cachedPassword = nil
            stopNetworkMonitor()
            log("Disconnected.")
            completeDisconnectCallbacks(true)

        case .credentialsRejected(let message):
            authenticationBlocked = true
            retryBlockedByFailure = false
            pendingWakeReconnect = false
            cachedPassword = nil
            phase = .needsCredentials
            cancelPendingReconnect()
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(true)

        case .accountLocked(let message):
            accountLockedMessage = message
            authenticationBlocked = true
            retryBlockedByFailure = true
            pendingWakeReconnect = false
            cachedPassword = nil
            phase = .accountLocked(message)
            cancelPendingReconnect()
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(true)

        case .certificateError(let message),
             .localServiceError(let message):
            retryBlockedByFailure = true
            wantsConnection = false
            pendingWakeReconnect = false
            cachedPassword = nil
            phase = .failed(message)
            cancelPendingReconnect()
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(outcome.cleanTermination)

        case .unclassified(let message):
            if pendingWakeReconnect && reconnectAttempt < 5 {
                log("\(message) Retrying after system wake...")
                completeDisconnectCallbacks(outcome.cleanTermination)
                if canAutoReconnect {
                    scheduleReconnect()
                    return
                }
            }
            retryBlockedByFailure = true
            wantsConnection = false
            pendingWakeReconnect = false
            cachedPassword = nil
            phase = .failed(message)
            cancelPendingReconnect()
            stopNetworkMonitor()
            log(message)
            completeDisconnectCallbacks(outcome.cleanTermination)

        case .transientNetworkError(let message):
            log(message)
            completeDisconnectCallbacks(true)
            let isSessionRenewalRequired = session.wasConnected && session.sessionLogs.contains { line in
                let lower = line.lowercased()
                return lower.contains("reconnect gave different") ||
                    lower.contains("cookie is no longer valid") ||
                    lower.contains("cstp rekey due")
            }
            if session.wasConnected && (isDisplayAsleep || isSessionRenewalRequired) {
                pendingWakeReconnect = true
            }
            if canAutoReconnect {
                scheduleReconnect()
            } else {
                phase = .idle
                wantsConnection = false
                pendingWakeReconnect = false
                cachedPassword = nil
                stopNetworkMonitor()
            }
        }
    }

    func screensDidSleep() {
        isDisplayAsleep = true
    }

    func screensDidWake() {
        isDisplayAsleep = false
        guard activeSession == nil, canAutoReconnect, phase == .reconnecting else { return }
        reconnectAttempt = 0
        log("Display woke up. Expediting VPN reconnect...")
        scheduleReconnect()
    }

    /// Coordinates macOS sleep transitions with active VPN sessions so stale pre-sleep tunnels are cleanly replaced on wake.
    func systemWillSleep() {
        isSystemSleeping = true
        guard (wantsConnection || activeSession != nil),
              phase != .disconnecting,
              !isPendingDeletion else { return }
        pendingWakeReconnect = true
        cancelPendingReconnect()
        cancelRecoveryTimer()
        if var session = activeSession {
            session.stopReason = .systemSleep
            session.tunnelRecovery = .waitingForNetwork
            activeSession = session
            processLifecycle = .stopping
            tunnelRecoveryState = .waitingForNetwork
            phase = .waitingForNetwork
            log("System going to sleep. Stopping active VPN session for clean reconnect on wake...")
            transport.stop(session: session.id)
        } else {
            tunnelRecoveryState = .waitingForNetwork
            phase = .waitingForNetwork
            log("System going to sleep. Waiting for wake to reconnect...")
        }
    }

    /// Triggered when macOS wakes from sleep (e.g., reopening MacBook lid).
    func systemDidWake() {
        let wasSleeping = isSystemSleeping
        isSystemSleeping = false
        guard (wantsConnection || pendingWakeReconnect || activeSession != nil),
              !isPendingDeletion else { return }
        if wantsConnection {
            pendingWakeReconnect = true
        }
        guard !authenticationBlocked, accountLockedMessage == nil else { return }
        retryBlockedByFailure = false
        reconnectAttempt = 0
        cancelRecoveryTimer()

        if var session = activeSession {
            if session.stopReason != .systemSleep && phase != .disconnecting {
                session.stopReason = .systemSleep
                activeSession = session
                processLifecycle = .stopping
                tunnelRecoveryState = .recovering
                phase = .recoveringConnection
                log("System woke from sleep. Stopping stale VPN session before reconnecting...")
                transport.stop(session: session.id)
            } else if wasSleeping {
                log("System woke from sleep. Waiting for previous VPN session cleanup to finish...")
            }
        } else if canAutoReconnect {
            log("System woke from sleep. Reconnecting VPN...")
            scheduleReconnect()
        }
    }

    /// Shared by NWPathMonitor and tests; coordinates network availability with process and tunnel recovery states.
    func networkChanged(available: Bool) {
        guard available != isNetworkAvailable else { return }
        isNetworkAvailable = available

        if !available {
            cancelPendingReconnect()
            cancelRecoveryTimer()
            if var session = activeSession, phase != .disconnecting {
                session.tunnelRecovery = .waitingForNetwork
                activeSession = session
                tunnelRecoveryState = .waitingForNetwork
                phase = .waitingForNetwork
                log("Network connectivity lost. Waiting for network...")
            } else if canAutoReconnect {
                tunnelRecoveryState = .waitingForNetwork
                phase = .waitingForNetwork
                log("Network connectivity lost. Waiting for network...")
            }
        } else {
            if var session = activeSession, phase != .disconnecting, session.stopReason != .systemSleep {
                if session.wasConnected || session.tunnelRecovery == .waitingForNetwork || session.tunnelRecovery == .recovering {
                    session.tunnelRecovery = .recovering
                    activeSession = session
                    tunnelRecoveryState = .recovering
                    phase = .recoveringConnection
                    log("Network restored. Waiting for VPN tunnel recovery confirmation...")
                    startRecoveryTimer(for: session.id)
                }
            } else if activeSession == nil {
                tunnelRecoveryState = .none
                scheduleReconnect()
            }
        }
    }

    private func startRecoveryTimer(for sessionID: UUID) {
        cancelRecoveryTimer()
        let generation = recoveryGeneration
        let timeout = recoveryTimeout
        recoveryTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(timeout)) } catch { return }
            guard let self, self.recoveryGeneration == generation,
                  var session = self.activeSession, session.id == sessionID,
                  session.tunnelRecovery == .recovering,
                  self.phase != .disconnecting else { return }

            let shouldAutoReconnect = (self.config.autoReconnect || self.pendingWakeReconnect) &&
                self.wantsConnection &&
                !self.authenticationBlocked &&
                self.accountLockedMessage == nil &&
                !self.retryBlockedByFailure &&
                !self.hasPendingConfigurationChanges &&
                !self.isPendingDeletion

            session.stopReason = shouldAutoReconnect ? .recoveryTimeoutAutoReconnect : .recoveryTimeoutManualRequired
            self.activeSession = session
            self.processLifecycle = .stopping
            self.phase = .disconnecting
            self.log("VPN tunnel did not confirm recovery within \(Int(timeout))s. Stopping previous session...")
            self.transport.stop(session: session.id)
        }
    }

    private func cancelRecoveryTimer() {
        recoveryGeneration = UUID()
        recoveryTask?.cancel()
        recoveryTask = nil
    }

    private func scheduleReconnect() {
        guard canAutoReconnect else { return }
        guard !isSystemSleeping, isNetworkAvailable else {
            tunnelRecoveryState = .waitingForNetwork
            phase = .waitingForNetwork
            return
        }
        cancelPendingReconnect()
        tunnelRecoveryState = .none
        phase = .reconnecting
        let generation = reconnectGeneration
        let delay = retryDelay(reconnectAttempt)
        reconnectAttempt += 1
        log("Retrying in \(Int(delay))s...")
        reconnectTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) } catch { return }
            guard let self, self.reconnectGeneration == generation,
                  self.canAutoReconnect, !self.isSystemSleeping, self.isNetworkAvailable else { return }
            let boundPassword = self.config.rememberCredentials ? self.loadPassword(self.config) : nil
            let password = boundPassword ?? self.cachedPassword
            guard let password, !password.isEmpty else {
                self.authenticationBlocked = true
                self.phase = .needsCredentials
                return
            }
            self.beginSession(password: password)
        }
    }

    private func cancelPendingReconnect() {
        reconnectGeneration = UUID()
        reconnectTask?.cancel()
        reconnectTask = nil
    }

    private func startNetworkMonitor() {
        if backgroundActivityToken == nil {
            backgroundActivityToken = ProcessInfo.processInfo.beginActivity(
                options: .userInitiatedAllowingIdleSystemSleep,
                reason: "Maintain active VPN connection and reconnect timers"
            )
        }
        guard monitorsNetwork else { return }
        if pathMonitor == nil {
            let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
            let generation = UUID()
            monitorGeneration = generation
            monitor.pathUpdateHandler = { [weak self] path in
                Task { @MainActor in
                    guard let self, self.monitorGeneration == generation else { return }
                    self.networkChanged(available: path.status == .satisfied)
                }
            }
            pathMonitor = monitor
            monitor.start(queue: DispatchQueue(label: "OpenConnectGUI.network"))
        }
        if sleepObserver == nil {
            sleepObserver = NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.willSleepNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.systemWillSleep()
                }
            }
        }
        if wakeObserver == nil {
            wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.didWakeNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.systemDidWake()
                }
            }
        }
        if screenSleepObserver == nil {
            screenSleepObserver = NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.screensDidSleepNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.screensDidSleep()
                }
            }
        }
        if screenWakeObserver == nil {
            screenWakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.screensDidWakeNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.screensDidWake()
                }
            }
        }
    }

    private func stopNetworkMonitor() {
        monitorGeneration = UUID()
        pathMonitor?.cancel()
        pathMonitor = nil
        if let backgroundActivityToken {
            ProcessInfo.processInfo.endActivity(backgroundActivityToken)
            self.backgroundActivityToken = nil
        }
        if let sleepObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(sleepObserver)
            self.sleepObserver = nil
        }
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
            self.wakeObserver = nil
        }
        if let screenSleepObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(screenSleepObserver)
            self.screenSleepObserver = nil
        }
        if let screenWakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(screenWakeObserver)
            self.screenWakeObserver = nil
        }
    }

    func clearLogs() {
        logs.removeAll()
    }

    private func log(_ text: String) {
        logs.append(text)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }
}
