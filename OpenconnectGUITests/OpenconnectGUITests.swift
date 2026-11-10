import Darwin
import Foundation
import Testing
#if SWIFT_PACKAGE
@testable import OpenConnectCore
#else
@testable import OpenconnectGUI
#endif

@MainActor
final class FakeTransport: VPNTransport {
    struct Start { let id: UUID; let config: VPNConfiguration; let password: String }
    var starts: [Start] = []
    var stops: [UUID] = []
    var callbacks: [UUID: @MainActor (VPNTransportEvent) -> Void] = [:]
    func start(session: UUID, config: VPNConfiguration, password: String, receive: @escaping @MainActor (VPNTransportEvent) -> Void) {
        starts.append(Start(id: session, config: config, password: password))
        callbacks[session] = receive
    }
    func stop(session: UUID) { stops.append(session) }
    func emit(_ event: VPNTransportEvent, index: Int = 0) { callbacks[starts[index].id]?(event) }
}

final class MemoryPasswords: VPNPasswordStore {
    var entries: [UUID: StoredCredential] = [:]
    var legacyPasswords: [UUID: String] = [:]
    var failSaves = false
    var failDeletes = false

    var values: [UUID: String] {
        Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0.value.password) })
    }

    func load(credentialID: UUID, expected: CredentialBinding) -> String? {
        guard let stored = entries[credentialID],
              stored.credentialID == credentialID,
              stored.binding == expected else {
            return nil
        }
        return stored.password
    }

    func save(_ password: String, credentialID: UUID, binding: CredentialBinding, label: String) throws {
        if failSaves { throw VPNServiceError.message("Keychain write unavailable") }
        entries[credentialID] = StoredCredential(credentialID: credentialID, binding: binding, password: password)
    }

    func delete(credentialID: UUID) throws {
        if failDeletes { throw VPNServiceError.message("Keychain delete unavailable") }
        entries[credentialID] = nil
    }

    func allCredentialIDs() throws -> Set<UUID> {
        Set(entries.keys)
    }

    func loadLegacy(for config: VPNConfiguration, migrationVersion: Int) throws -> String? {
        guard config.rememberCredentials, migrationVersion < VPNConfiguration.currentCredentialMigrationVersion else {
            return nil
        }
        return legacyPasswords[config.id]
    }

    func deleteLegacyV1(for profileID: UUID) throws {
        legacyPasswords[profileID] = nil
    }
}

@Suite @MainActor
struct ConnectionTests {
    func profile(auto: Bool = false, remember: Bool = false) -> VPNConfiguration {
        VPNConfiguration(name: "Test", serverAddress: "https://vpn.example.invalid", username: "test", rememberCredentials: remember, autoReconnect: auto)
    }
    func state(_ config: VPNConfiguration, _ transport: FakeTransport, recoveryTimeout: TimeInterval = 15.0, loadPassword: @escaping (VPNConfiguration) -> String? = { _ in nil }) -> VPNConnectionState {
        VPNConnectionState(config: config, transport: transport, monitorsNetwork: false, recoveryTimeout: recoveryTimeout, loadPassword: loadPassword, retryDelay: { _ in 0.01 }, notify: { _, _ in })
    }
    func settle() async throws { try await Task.sleep(for: .milliseconds(80)) }

    @Test func duplicateConnectIsRejectedSynchronously() {
        let transport = FakeTransport(), config = profile()
        let state = state(config, transport)
        state.connect(with: "first")
        state.connect(with: "second")
        #expect(transport.starts.count == 1)
        #expect(state.phase == .authorizing)
    }

    @Test func cancellationDuringAuthorizationIgnoresSuccessAndWaitsForExit() {
        let transport = FakeTransport()
        let connection = self.state(profile(), transport)
        connection.connect(with: "password")
        connection.disconnect()
        transport.emit(.connecting)
        transport.emit(.output(Data("Configured as 192.0.2.1\n".utf8)))
        #expect(connection.phase == .disconnecting)
        #expect(!connection.canConnect)
        #expect(transport.stops.count == 1)
        transport.emit(.ended(0))
        #expect(connection.phase == .idle)
    }

    @Test func staleExitAndLogsCannotMutateNewConnection() {
        let transport = FakeTransport()
        let current = state(profile(), transport)
        current.connect(with: "first")
        current.disconnect()
        transport.emit(.ended(0))
        current.connect(with: "second")
        transport.emit(.connecting, index: 1)
        transport.emit(.ended(1), index: 0)
        transport.emit(.output(Data("Authentication failed\nConfigured as 1.2.3.4\n".utf8)), index: 0)
        #expect(current.phase == .connecting)
        #expect(!current.logs.contains("Authentication failed"))
        current.disconnect()
        #expect(transport.stops.last == transport.starts[1].id)
    }

    @Test func authenticationFailureBlocksAllNetworkRetries() async throws {
        let transport = FakeTransport(), config = profile(auto: true)
        let connection = state(config, transport)
        connection.connect(with: "wrong")
        transport.emit(.output(Data("Authentication failed".utf8))) // final line has no newline
        transport.emit(.ended(1))
        #expect(connection.phase == .needsCredentials)
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        try await settle()
        #expect(transport.starts.count == 1)
        connection.connect(with: "correct")
        #expect(transport.starts.last?.password == "correct")
    }

    @Test func networkErrorDoesNotBecomeCredentialFailure() async throws {
        let transport = FakeTransport()
        let current = state(profile(auto: true), transport)
        current.connect(with: "password")
        transport.emit(.output(Data("Failed to open HTTPS connection\nFailed to obtain WebVPN cookie\n".utf8)))
        transport.emit(.ended(1))
        try await settle()
        #expect(transport.starts.count == 2)
        current.disconnect()
    }

    @Test func passwordEditUpdatesNextRetry() async throws {
        let transport = FakeTransport(), config = profile(auto: true, remember: true)
        let connection = state(config, transport)
        connection.connect(with: "old")
        connection.credentialsChanged("new")
        transport.emit(.output(Data("Failed to open HTTPS connection\n".utf8)))
        transport.emit(.ended(1))
        try await settle()
        #expect(transport.starts.count == 2)
        #expect(transport.starts.last?.password == "new")
        connection.disconnect()
    }

    @Test func changingServerNeverReusesOldPassword() async throws {
        let transport = FakeTransport()
        var config = profile(auto: true)
        let connection = state(config, transport)
        connection.connect(with: "old")
        config.serverAddress = "https://different.example.invalid"
        connection.updateConfig(config)
        transport.emit(.ended(1))
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        try await settle()
        #expect(transport.starts.count == 1)
    }

    @Test func disablingReconnectCancelsScheduledAttempt() async throws {
        let transport = FakeTransport()
        var config = profile(auto: true)
        let connection = state(config, transport)
        connection.connect(with: "secret")
        transport.emit(.output(Data("Connection timed out\n".utf8)))
        transport.emit(.ended(1))
        config.autoReconnect = false
        connection.updateConfig(config)
        try await settle()
        #expect(transport.starts.count == 1)
        #expect(connection.phase == .idle)
    }

    @Test func splitSuccessMessageIsRecognized() {
        let transport = FakeTransport(), config = profile()
        let connection = state(config, transport)
        connection.connect(with: "password")
        transport.emit(.output(Data("Confi".utf8)))
        #expect(!connection.isConnected)
        transport.emit(.output(Data("gured as 192.0.2.1\n".utf8)))
        #expect(connection.isConnected)
    }

    @Test func connectionLookupHasStableIdentityAndDeletionWaits() {
        let transport = FakeTransport()
        let store = ConnectionStore(makeState: { state($0, transport) })
        let config = profile()
        store.register(config)
        let a = store.connection(for: config), b = store.connection(for: config)
        #expect(a === b)
        a?.connect(with: "password")
        store.remove(config)
        #expect(store.connection(for: config) == nil)
        #expect(store.hasActiveSessions)
        transport.emit(.ended(0))
        #expect(!store.hasActiveSessions)
    }

    @Test func rememberOffDoesNotPersistPasswordAndNewPasswordReachesRetry() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let passwords = MemoryPasswords(), transport = FakeTransport()
        let connections = ConnectionStore(makeState: { state($0, transport, loadPassword: { passwords.load(for: $0) }) })
        let store = VPNConfigurationStore(configFileURL: directory.appendingPathComponent("profiles.json"), passwords: passwords, connections: connections)
        var config = profile(auto: true)
        try store.add(config, password: "not-persisted")
        #expect(passwords.values.isEmpty)
        connections.connection(for: config)?.connect(with: "old")
        config.rememberCredentials = true
        try store.update(config, password: "new")
        let savedConfig = try #require(store.configurations.first)
        #expect(passwords.load(for: savedConfig) == "new")
        transport.emit(.output(Data("Failed to open HTTPS connection\n".utf8)))
        transport.emit(.ended(1))
        try await settle()
        #expect(transport.starts.last?.password == "new")
        connections.disconnectAll()
    }

    @Test func keychainFailureIsReportedWithoutPublishingNewConfig() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let passwords = MemoryPasswords()
        passwords.failSaves = true
        let store = VPNConfigurationStore(configFileURL: directory.appendingPathComponent("profiles.json"), passwords: passwords)
        #expect(throws: (any Error).self) { try store.add(profile(remember: true), password: "secret") }
        #expect(store.configurations.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("profiles.json").path))
    }

    @Test func editingActiveConnectionPreservesActiveTargetUntilControlledReconnect() {
        let transport = FakeTransport()
        let configA = VPNConfiguration(name: "Corp VPN", serverAddress: "https://vpn-a.example.invalid", username: "alice", protocolType: "anyconnect", rememberCredentials: false, autoReconnect: true)
        let connection = state(configA, transport)
        connection.connect(with: "pass-a")
        transport.emit(.output(Data("Configured as 10.0.0.2\n".utf8)))
        #expect(connection.isConnected)
        #expect(connection.activeConfiguration?.serverAddress == "https://vpn-a.example.invalid")
        #expect(!connection.hasPendingConfigurationChanges)

        var configB = configA
        configB.serverAddress = "https://vpn-b.example.invalid"
        configB.username = "bob"
        configB.protocolType = "gp"
        connection.updateConfig(configB)

        // Active tunnel remains on A while next connection is B.
        #expect(connection.isConnected)
        #expect(connection.activeConfiguration?.serverAddress == "https://vpn-a.example.invalid")
        #expect(connection.activeConfiguration?.username == "alice")
        #expect(connection.config.serverAddress == "https://vpn-b.example.invalid")
        #expect(connection.hasPendingConfigurationChanges)

        // Triggering reconnect-to-apply without matching credentials for B stops A first, then asks for credentials.
        connection.reconnectToApplyChanges(with: nil)
        #expect(connection.phase == .disconnecting)
        #expect(transport.stops.count == 1)
        transport.emit(.ended(0), index: 0)
        #expect(connection.phase == .needsCredentials)
        #expect(transport.starts.count == 1)

        // Now connect with B's password.
        connection.connect(with: "pass-b")
        transport.emit(.output(Data("Configured as 10.0.0.3\n".utf8)), index: 1)
        #expect(connection.isConnected)
        #expect(connection.activeConfiguration?.serverAddress == "https://vpn-b.example.invalid")
        #expect(!connection.hasPendingConfigurationChanges)
    }

    @Test func networkRecoveryRequiresFreshTunnelConfirmationAndHandlesTimeouts() async throws {
        let transport = FakeTransport()
        let config = profile(auto: true)
        let connection = state(config, transport, recoveryTimeout: 0.05)
        connection.connect(with: "secret")
        transport.emit(.output(Data("Configured as 10.0.0.1\n".utf8)))
        #expect(connection.isConnected)

        // 1. Brief network drop cancels green connected state, keeps existing process.
        connection.networkChanged(available: false)
        #expect(!connection.isConnected)
        #expect(connection.phase == .waitingForNetwork)
        #expect(transport.stops.isEmpty)

        // 2. Network restores -> enters recoveringConnection, still not green until tunnel confirms.
        connection.networkChanged(available: true)
        #expect(!connection.isConnected)
        #expect(connection.phase == .recoveringConnection)
        transport.emit(.output(Data("Established DTLS connection\n".utf8)))
        #expect(connection.isConnected)
        #expect(connection.phase == .connected)
        #expect(transport.starts.count == 1)

        // 3. Another network drop & restore, but gateway does not respond within recovery window:
        // must stop old session first, wait for exit, then start new session.
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        #expect(connection.phase == .recoveringConnection)
        try await settle()
        #expect(transport.stops.count == 1)
        #expect(transport.starts.count == 1) // Second session has NOT started while first is still stopping!
        transport.emit(.ended(0), index: 0)
        try await settle()
        #expect(transport.starts.count == 2) // Started only after old session stopped!
        connection.disconnect()
    }

    @Test func recoveryTimeoutWithAutoReconnectOffStopsOldSessionAndRequiresManualAction() async throws {
        let transport = FakeTransport()
        let config = profile(auto: false)
        let connection = state(config, transport, recoveryTimeout: 0.04)
        connection.connect(with: "secret")
        transport.emit(.output(Data("Configured as 10.0.0.1\n".utf8)))
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        try await settle()
        #expect(transport.stops.count == 1)
        transport.emit(.ended(0), index: 0)
        if case .failed = connection.phase {
            // expected manual action state
        } else {
            Issue.record("Expected failed state after recovery timeout with autoReconnect disabled, got \(connection.phase)")
        }
        #expect(transport.starts.count == 1)
    }

    @Test func sleepAndWakeStopsStaleTunnelAndAutomaticallyReconnects() async throws {
        let transport = FakeTransport()
        let config = profile(auto: false)
        let connection = state(config, transport)
        connection.connect(with: "secret")
        transport.emit(.output(Data("Configured as 10.0.0.1\n".utf8)))
        #expect(connection.isConnected)

        // Closing MacBook lid stops the active session and waits for wake.
        connection.systemWillSleep()
        #expect(connection.phase == .waitingForNetwork)
        #expect(transport.stops.count == 1)

        // Old session terminates (even if forced after socket hang), still waiting while asleep.
        transport.emit(
            .ended(VPNExitOutcome(status: 15, processConfirmedStopped: true, wasForceKilled: true, logsComplete: true, networkCleanupComplete: false)),
            index: 0
        )
        #expect(connection.phase == .waitingForNetwork)
        #expect(transport.starts.count == 1)

        // Opening MacBook lid wakes system and automatically starts a fresh session.
        connection.systemDidWake()
        try await settle()
        #expect(transport.starts.count == 2)
        #expect(transport.starts.last?.password == "secret")
        transport.emit(.output(Data("Configured as 10.0.0.2\n".utf8)), index: 1)
        #expect(connection.isConnected)
        connection.disconnect()
    }

    @Test func expiredTunnelCookieAfterConnectedSessionReauthenticatesInsteadOfBlockingCredentials() async throws {
        let transport = FakeTransport()
        let config = profile(auto: true)
        let connection = state(config, transport)
        connection.connect(with: "secret")
        transport.emit(.tunnelStarting, index: 0)
        transport.emit(.output(Data("Configured as 10.0.0.1\n".utf8)), index: 0)
        #expect(connection.isConnected)

        // Gateway invalidates cookie during sleep; tunnel exits with session authentication failure.
        transport.emit(.output(Data("Session authentication failed\nCookie was rejected\n".utf8)), index: 0)
        transport.emit(.ended(2), index: 0)

        #expect(connection.phase != .needsCredentials)
        try await settle()
        #expect(transport.starts.count == 2)
        #expect(transport.starts.last?.password == "secret")
        connection.disconnect()
    }

    @Test func screenOffCstpRekeyWithServercertWarningAutomaticallyReauthenticatesInsteadOfCertError() async throws {
        let transport = FakeTransport()
        // Even if profile was saved earlier with autoReconnect == false, CSTP rekey / screen-off IP rotation renews session.
        let config = profile(auto: false)
        let connection = state(config, transport)
        connection.connect(with: "secret")
        transport.emit(.tunnelStarting, index: 0)
        transport.emit(
            .output(
                Data(
                    """
                    SSL negotiation with ywl.anylink.pub
                    Server certificate verify failed: signer not found
                    Connected to HTTPS on ywl.anylink.pub with ciphersuite (TLS1.3)-(ECDHE-X25519)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
                    Got CONNECT response: HTTP/1.1 200 OK
                    Configured as 192.168.90.128, with SSL connected and DTLS disabled
                    """.utf8 + Data("\n".utf8)
                )
            ),
            index: 0
        )
        #expect(connection.isConnected)

        connection.screensDidSleep()
        transport.emit(
            .output(
                Data(
                    """
                    CSTP Dead Peer Detection detected dead peer!
                    SSL negotiation with ywl.anylink.pub
                    Server certificate verify failed: signer not found
                    Connected to HTTPS on ywl.anylink.pub with ciphersuite (TLS1.3)-(ECDHE-X25519)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
                    Got CONNECT response: HTTP/1.1 200 OK
                    Reconnect gave different Legacy IP address (192.168.90.129 != 192.168.90.128)
                    Cookie is no longer valid, ending session
                    Reconnect failed
                    Cookie was rejected by server; exiting.
                    """.utf8 + Data("\n".utf8)
                )
            ),
            index: 0
        )
        transport.emit(.ended(2), index: 0)

        if case .failed = connection.phase {
            Issue.record("Expected automatic reconnect instead of certificate failure, got \(connection.phase)")
        }
        try await settle()
        #expect(transport.starts.count == 2)
        #expect(transport.starts.last?.password == "secret")
        transport.emit(.tunnelStarting, index: 1)
        transport.emit(.output(Data("Configured as 192.168.90.129\n".utf8)), index: 1)
        #expect(connection.isConnected)
        connection.disconnect()
    }
}

@Suite @MainActor
struct PersistenceFaultInjectionTests {
    @Test func fileWriteFailureRollsBackNewCredentialAndPreservesOldServerAndPassword() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("profiles.json")
        let passwords = MemoryPasswords()
        var failNextFileWrite = false

        let writer: (Data, URL) throws -> Void = { data, url in
            if failNextFileWrite {
                throw VPNServiceError.message("Simulated disk full error")
            }
            try data.write(to: url, options: .atomic)
        }

        let store = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords, fileWriter: writer)
        let initial = VPNConfiguration(name: "HQ", serverAddress: "https://old.example.invalid", username: "alice", protocolType: "anyconnect", rememberCredentials: true)
        try store.add(initial, password: "virtual-password-old")

        let committedOld = try #require(store.configurations.first)
        let oldCredentialID = try #require(committedOld.credentialID)
        #expect(passwords.entries.count == 1)
        #expect(store.savedPassword(for: committedOld) == "virtual-password-old")

        // Inject file write failure during server + password update.
        failNextFileWrite = true
        var updated = committedOld
        updated.serverAddress = "https://new.example.invalid"
        #expect(throws: (any Error).self) {
            try store.update(updated, password: "virtual-password-new")
        }

        // In-memory and Keychain must still hold only the intact old credential; new item was rolled back.
        #expect(passwords.entries.count == 1)
        #expect(passwords.entries[oldCredentialID]?.password == "virtual-password-old")
        #expect(store.configurations.first?.serverAddress == "https://old.example.invalid")
        #expect(store.savedPassword(for: committedOld) == "virtual-password-old")

        // Reloading from disk must yield the exact old configuration and old password, never a mismatch.
        let reloaded = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        let diskConfig = try #require(reloaded.configurations.first)
        #expect(diskConfig.serverAddress == "https://old.example.invalid")
        #expect(diskConfig.credentialID == oldCredentialID)
        #expect(reloaded.savedPassword(for: diskConfig) == "virtual-password-old")
    }

    @Test func credentialBindingMismatchRejectsPasswordAndOrphanCleanupRespectsLoadStatus() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("profiles.json")
        let passwords = MemoryPasswords()

        let store = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        let config = VPNConfiguration(name: "Branch", serverAddress: "https://branch.example.invalid", username: "user1", protocolType: "gp", rememberCredentials: true)
        try store.add(config, password: "virtual-secret-1")
        let saved = try #require(store.configurations.first)
        let validCredID = try #require(saved.credentialID)

        // Simulate an orphaned credential left behind by an interrupted process.
        let orphanID = UUID()
        try passwords.save("virtual-orphan", credentialID: orphanID, binding: saved.credentialBinding, label: "Orphan")
        #expect(passwords.entries.count == 2)

        // If the config file is corrupted, loading fails and orphan cleanup MUST NOT delete any credentials.
        try Data("{corrupted-json".utf8).write(to: fileURL)
        let failedStore = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        #expect(failedStore.loadFailed)
        #expect(passwords.entries.count == 2)

        // Restore valid config file: startup orphan cleanup removes only the unreferenced orphan.
        try JSONEncoder().encode([saved]).write(to: fileURL)
        let recoveredStore = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        #expect(!recoveredStore.loadFailed)
        #expect(passwords.entries.keys.contains(validCredID))
        #expect(!passwords.entries.keys.contains(orphanID))

        // If server/username/protocol is tampered on disk while keeping credentialID, binding check rejects it.
        var tampered = saved
        tampered.serverAddress = "https://attacker.example.invalid"
        #expect(passwords.load(for: tampered) == nil)
    }

    @Test func turningOffRememberCommitsConfigAndSchedulesRetryWhenKeychainDeleteFails() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("profiles.json")
        let passwords = MemoryPasswords()

        let store = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords, cleanupRetryDelay: 0.03)
        let initial = VPNConfiguration(name: "Edge", serverAddress: "https://edge.example.invalid", username: "ops", rememberCredentials: true)
        try store.add(initial, password: "virtual-password")
        var current = try #require(store.configurations.first)
        let oldCredID = try #require(current.credentialID)

        // Fail Keychain delete when turning off Remember Credentials.
        passwords.failDeletes = true
        current.rememberCredentials = false
        try store.update(current)

        let updated = try #require(store.configurations.first)
        #expect(!updated.rememberCredentials)
        #expect(updated.credentialID == nil)
        #expect(store.errorMessage?.contains("Configuration was saved") == true)
        #expect(store.pendingCleanupCredentialIDs.contains(oldCredID))

        // Once Keychain becomes available again, background retry cleans up the retired credential.
        passwords.failDeletes = false
        try await Task.sleep(for: .milliseconds(80))
        #expect(!store.pendingCleanupCredentialIDs.contains(oldCredID))
        #expect(passwords.entries.isEmpty)
    }

    @Test func deletingActiveProfileWaitsForDisconnectAndRetainsEntryOnTeardownFailure() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("profiles.json")
        let passwords = MemoryPasswords()
        let transport = FakeTransport()
        let connections = ConnectionStore(makeState: {
            VPNConnectionState(config: $0, transport: transport, monitorsNetwork: false, loadPassword: { _ in nil }, retryDelay: { _ in 0.01 }, notify: { _, _ in })
        })
        let store = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords, connections: connections)
        let config = VPNConfiguration(name: "ActiveVPN", serverAddress: "https://active.example.invalid", username: "admin", rememberCredentials: true)
        try store.add(config, password: "virtual-pass")
        let saved = try #require(store.configurations.first)
        let state = try #require(connections.connection(for: saved))

        // Start connecting and attempt to delete while active.
        state.connect(with: "virtual-pass")
        try store.remove(saved)
        // Profile is retained while disconnecting!
        #expect(store.configurations.count == 1)
        #expect(state.isPendingDeletion)

        // Simulate a failed/unconfirmed process stop: profile and control entry must be kept!
        transport.emit(.ended(VPNExitOutcome(status: -1, processConfirmedStopped: false, wasForceKilled: false, logsComplete: true, networkCleanupComplete: false)), index: 0)
        #expect(store.configurations.count == 1)
        #expect(!state.isPendingDeletion)
        #expect(store.errorMessage != nil)

        // Now retry removal and let the process stop cleanly: profile and credential are removed.
        try store.remove(saved)
        transport.emit(.ended(VPNExitOutcome(status: 0, processConfirmedStopped: true, wasForceKilled: false, logsComplete: true, networkCleanupComplete: true)), index: 0)
        #expect(store.configurations.isEmpty)
        #expect(passwords.entries.isEmpty)
    }

    @Test func legacyMigrationUsesVersionedCommitAndNeverReimportsForgottenCredentials() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("profiles.json")
        let passwords = MemoryPasswords()

        let legacyID = UUID()
        passwords.legacyPasswords[legacyID] = "virtual-legacy-secret"
        let legacyJSON = """
        [{"id":"\(legacyID.uuidString)","name":"Legacy","serverAddress":"https://legacy.example.invalid","username":"user","protocolType":"anyconnect","rememberCredentials":true,"autoReconnect":false,"credentialsMigrated":false}]
        """
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(legacyJSON.utf8).write(to: fileURL)

        // 1. If file write fails during migration, newly created v2 credential is rolled back.
        let failedMigrationStore = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords, fileWriter: { _, _ in
            throw VPNServiceError.message("Migration write failed")
        })
        #expect(failedMigrationStore.loadFailed)
        #expect(passwords.entries.isEmpty)
        #expect(passwords.legacyPasswords[legacyID] == "virtual-legacy-secret")

        // 2. Successful migration commits credentialID and migration version, and cleans up v1 legacy entry.
        let store = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        var migrated = try #require(store.configurations.first)
        #expect(migrated.credentialID != nil)
        #expect(migrated.credentialMigrationVersion == VPNConfiguration.currentCredentialMigrationVersion)
        #expect(store.savedPassword(for: migrated) == "virtual-legacy-secret")

        // 3. Forget credentials and verify re-opening the store never re-imports any legacy password.
        passwords.legacyPasswords[legacyID] = "stale-legacy-password"
        migrated.rememberCredentials = false
        try store.update(migrated)
        let reloaded = VPNConfigurationStore(configFileURL: fileURL, passwords: passwords)
        let afterReload = try #require(reloaded.configurations.first)
        #expect(!afterReload.rememberCredentials)
        #expect(reloaded.savedPassword(for: afterReload) == nil)
    }

    @Test func localEncryptedStoreEncryptsAtRestAndMigratesLegacyPlaintext() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("credentials.v2.json")
        let keyURL = directory.appendingPathComponent(".vault.key")

        let credID = UUID()
        let binding = CredentialBinding(
            profileID: UUID(),
            server: "https://vpn.example.invalid",
            username: "alice",
            protocolType: "anyconnect"
        )
        let legacyPlaintext: [String: StoredCredential] = [
            credID.uuidString: StoredCredential(credentialID: credID, binding: binding, password: "super-secret-plaintext-value")
        ]
        try JSONEncoder().encode(legacyPlaintext).write(to: storeURL, options: .atomic)

        // Reading migrates plaintext JSON on disk into AES-GCM ciphertext and strips plaintext from disk.
        let migrated = KeychainService.readLocalStoreUnlocked(storeURL: storeURL, keyURL: keyURL)
        let record = try #require(migrated[credID.uuidString])
        let rawOnDisk = try String(contentsOf: storeURL, encoding: .utf8)
        #expect(!rawOnDisk.contains("super-secret-plaintext-value"))
        #expect(KeychainService.openPassword(record, expectedID: credID, expectedBinding: binding, keyURL: keyURL) == "super-secret-plaintext-value")

        // Tampering with binding rejects decryption.
        let tamperedBinding = CredentialBinding(
            profileID: binding.profileID,
            server: "https://evil.example.invalid",
            username: "alice",
            protocolType: "anyconnect"
        )
        #expect(KeychainService.openPassword(record, expectedID: credID, expectedBinding: tamperedBinding, keyURL: keyURL) == nil)
    }
}

@Suite @MainActor
struct ProtocolFailureClassificationTests {
    @Test func pulseAndMultiProtocolOutputsClassifyLockoutCredentialsCertAndNetworkCorrectly() async throws {
        let samples: [(String, String, VPNFailureKind)] = [
            ("pulse", "Connected to 192.0.2.1:443\nAuthentication failure: Account locked\nFailed to complete authentication\n", .accountLocked("Account is locked on the pulse gateway. Unlock your account, then connect manually.")),
            ("pulse", "Authentication failure: Client certificate is required\nFailed to complete authentication\n", .certificateError("Certificate validation or client certificate error for pulse. Verify certificate settings and retry manually.")),
            ("pulse", "Authentication failure: Invalid username or password\nFailed to complete authentication\n", .credentialsRejected("Authentication failed. Verify or update your credentials to retry.")),
            ("anyconnect", "POST https://vpn.example.invalid/\nLogin failed.\nFailed to obtain WebVPN cookie\n", .credentialsRejected("Authentication failed. Verify or update your credentials to retry.")),
            ("gp", "Portal reports GlobalProtect gateway login failed\nFailed to complete authentication\n", .credentialsRejected("Authentication failed. Verify or update your credentials to retry.")),
            ("nc", "Your account is currently locked\nFailed to complete authentication\n", .accountLocked("Account is locked on the nc gateway. Unlock your account, then connect manually.")),
            ("fortinet", "Server certificate verify failed: signer not found\nCreating SSL connection failed\n", .certificateError("Certificate validation or client certificate error for fortinet. Verify certificate settings and retry manually.")),
            ("f5", "Failed to open HTTPS connection to vpn.example.invalid\nFailed to complete authentication\n", .transientNetworkError("Temporary network error (f5, status 1).")),
            ("array", "Failed to complete authentication\n", .unclassified("Connection ended with an unclassified error (stage: authenticating, status: 1). Review logs and retry manually."))
        ]

        for (proto, rawLog, expected) in samples {
            let lines = rawLog.components(separatedBy: .newlines).filter { !$0.isEmpty }
            let actual = VPNFailureClassifier.classify(
                protocolType: proto,
                stage: .authenticating,
                outcome: VPNExitOutcome(status: 1),
                wasConnected: false,
                userCancelled: false,
                explicitFailure: nil,
                logs: lines
            )
            #expect(actual == expected)
        }
    }

    @Test func accountLockoutCannotBeBypassedByPasswordUpdateOrNetworkRestore() async throws {
        let transport = FakeTransport()
        let config = VPNConfiguration(name: "PulseCorp", serverAddress: "https://pulse.example.invalid", username: "alice", protocolType: "pulse", rememberCredentials: true, autoReconnect: true)
        let connection = VPNConnectionState(config: config, transport: transport, monitorsNetwork: false, loadPassword: { _ in "virtual-updated" }, retryDelay: { _ in 0.01 }, notify: { _, _ in })

        connection.connect(with: "virtual-initial")
        transport.emit(.output(Data("Authentication failure: Account locked\nFailed to complete authentication\n".utf8)))
        transport.emit(.ended(2))

        #expect(connection.isAccountLocked)
        // Updating saved password or toggling network must NOT trigger auto-reconnect while locked!
        connection.credentialsChanged("virtual-updated")
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        try await Task.sleep(for: .milliseconds(80))
        #expect(transport.starts.count == 1)
        #expect(connection.isAccountLocked)

        // Only an explicit manual connect after unlocking clears the lockout state.
        connection.connect(with: "virtual-unlocked")
        #expect(transport.starts.count == 2)
        #expect(!connection.isAccountLocked)
    }

    @Test func unclassifiedAndCertificateFailuresDoNotAutoRetryOnNetworkFlap() async throws {
        let transport = FakeTransport()
        let config = VPNConfiguration(name: "CertTest", serverAddress: "https://cert.example.invalid", username: "alice", protocolType: "anyconnect", rememberCredentials: true, autoReconnect: true)
        let connection = VPNConnectionState(config: config, transport: transport, monitorsNetwork: false, loadPassword: { _ in "virtual-pass" }, retryDelay: { _ in 0.01 }, notify: { _, _ in })

        connection.connect(with: "virtual-pass")
        transport.emit(.output(Data("Failed to complete authentication\n".utf8)))
        transport.emit(.ended(1))
        if case .failed = connection.phase {} else {
            Issue.record("Expected .failed phase for unclassified authentication exit")
        }
        connection.networkChanged(available: false)
        connection.networkChanged(available: true)
        try await Task.sleep(for: .milliseconds(80))
        #expect(transport.starts.count == 1)
    }

    @Test func authGroupPromptExtractsChoicesAndConnectsWithSelectedGroup() {
        let transport = FakeTransport()
        let config = VPNConfiguration(
            name: "GroupTest",
            serverAddress: "ywl.anylink.pub:22877",
            username: "yilaoshi17",
            protocolType: "anyconnect",
            rememberCredentials: true,
            autoReconnect: true
        )
        let connection = VPNConnectionState(
            config: config,
            transport: transport,
            monitorsNetwork: false,
            loadPassword: { _ in "virtual-pass" },
            retryDelay: { _ in 0.01 },
            notify: { _, _ in }
        )

        connection.connect(with: "virtual-pass")
        transport.emit(
            .output(
                Data(
                    "XML POST enabled\nGROUP: [ywl|Professor Yi's Research Group|课题组A|课题组B]:***\nUser input required in non-interactive mode\nFailed to complete authentication\n".utf8
                )
            )
        )
        transport.emit(.ended(1))

        #expect(connection.isSelectingGroup)
        #expect(connection.availableGroups == ["ywl", "Professor Yi's Research Group", "课题组A", "课题组B"])

        var updated = config
        updated.authGroup = "Professor Yi's Research Group"
        connection.connectWithSelectedGroup("Professor Yi's Research Group", updatedConfig: updated)

        #expect(!connection.isSelectingGroup)
        #expect(transport.starts.count == 2)
        #expect(transport.starts.last?.config.trimmedAuthGroup == "Professor Yi's Research Group")
    }
}

struct ProtocolAndProcessTests {
    @Test func utf8CanSplitAtEveryByte() {
        var buffer = VPNLineBuffer(), lines: [String] = []
        let message = "已连接🙂\nAuthentication failed"
        for byte in message.utf8 { lines += buffer.append(Data([byte])) }
        lines += buffer.append(Data(), final: true)
        #expect(lines == ["已连接🙂", "Authentication failed"])
    }

    @Test func authenticationOutputIsParsedWithoutShellEvaluation() throws {
        let output = "COOKIE='abc'def'\nCONNECT_URL='https://vpn.example.invalid'\nFINGERPRINT='sha256:abcd'\nRESOLVE="
        let result = try AuthenticationResult(data: Data(output.utf8))
        let request = try result.request(protocolType: "anyconnect", originalServer: "https://vpn.example.invalid")
        #expect(request.cookie == "abc'def")
        #expect(request.resolve == nil)
        #expect(throws: (any Error).self) { try AuthenticationResult.unquote("$(touch /tmp/never-run)") }
        #expect(throws: (any Error).self) { try AuthenticationResult.unquote("'safe'; arbitrary-command") }
    }

    @Test func tunnelRejectsOptionInjectionAndCredentialLineBreaks() {
        for server in ["--script=/tmp/evil", "https://host\n--script=x", "http://host", "https://user:pass@host"] {
            #expect(!TunnelRequest.validServer(server))
        }
        let request = TunnelRequest(server: "https://vpn.example.invalid", protocolType: "anyconnect", cookie: "one\ntwo", fingerprint: "sha256:abcd", resolve: nil)
        #expect(throws: (any Error).self) { try request.validate() }
        let maliciousProtocol = TunnelRequest(server: "https://vpn.example.invalid", protocolType: "anyconnect --script=evil", cookie: "secret", fingerprint: "sha256:abcd", resolve: nil)
        #expect(throws: (any Error).self) { try maliciousProtocol.validate() }
    }

    @Test func fixedArgumentsDoNotExposeCookieOrAcceptScriptOverride() throws {
        let request = TunnelRequest(server: "https://vpn.example.invalid", protocolType: "anyconnect", cookie: "private-cookie", fingerprint: "sha256:abcd", resolve: nil)
        try request.validate()
        let args = request.arguments(script: "/protected/vpnc-script")
        #expect(!args.joined().contains("private-cookie"))
        #expect(args.contains("--cookie-on-stdin"))
        #expect(args.contains("--script='/protected/vpnc-script'"))
        #expect(args.suffix(2) == ["--", request.server])

        let runnerArgs = request.arguments(scriptRunner: "/protected/OpenConnectHelper")
        #expect(runnerArgs.contains("--script='/protected/OpenConnectHelper' --vpnc-script-runner"))
        #expect(VPNScriptRunner.validateArguments(["/protected/OpenConnectHelper", "--vpnc-script-runner"]))
        #expect(!VPNScriptRunner.validateArguments(["/protected/OpenConnectHelper", "--vpnc-script-runner", "/tmp/evil.sh"]))
        #expect(!VPNScriptRunner.validateArguments(["/protected/OpenConnectHelper", "/tmp/evil.sh"]))
    }

    @Test func legacyRuleMigrationPreservesCustomRulesAndOtherUsers() {
        let exact = "tester ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect, /bin/kill\n"
        #expect(LegacySudoersRule.matches(exact, username: "tester"))
        #expect(!LegacySudoersRule.matches(exact, username: "someone-else"))
        #expect(!LegacySudoersRule.matches(exact + "# custom content\n", username: "tester"))
    }

    @Test func protectedRuntimeRejectsUserOwnedFiles() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(throws: (any Error).self) { try SecureRuntime.validateProtectedPath(url) }
    }

    @Test func processDrainsOutputBeforeReportingExit() async {
        let child = ManagedProcess()
        let result: (String, Int32) = await withCheckedContinuation { continuation in
            var output = Data()
            child.start(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "printf 'Confi'; printf 'gured as 192.0.2.1\\n'"], input: Data(), environment: SecureRuntime.environment,
                        started: {}, stdout: { output.append($0) }, stderr: { _ in },
                        exited: { continuation.resume(returning: (String(decoding: output, as: UTF8.self), $0)) },
                        failed: { continuation.resume(returning: ($0, -1)) })
        }
        #expect(result.0 == "Configured as 192.0.2.1\n")
        #expect(result.1 == 0)
    }

    @Test func processCancelledBeforeLaunchNeverRuns() async {
        let child = ManagedProcess()
        child.stop()
        let result: Bool = await withCheckedContinuation { continuation in
            var started = false
            child.start(executable: URL(fileURLWithPath: "/usr/bin/true"), arguments: [], input: Data(), environment: SecureRuntime.environment,
                        started: { started = true }, stdout: { _ in }, stderr: { _ in },
                        exited: { _ in continuation.resume(returning: started) },
                        failed: { _ in continuation.resume(returning: true) })
        }
        #expect(!result)
    }

    @Test func fixedScriptPathWithSpacesAndQuotesExecutesAsOnePath() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("VPN test '\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let script = folder.appendingPathComponent("test script")
        try Data("#!/bin/sh\nprintf 'quoted-path-ok'\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let request = TunnelRequest(server: "https://vpn.example.invalid", protocolType: "anyconnect", cookie: "x", fingerprint: "sha256:abcd", resolve: nil)
        let argument = try #require(request.arguments(script: script.path).first { $0.hasPrefix("--script=") })
        let command = String(argument.dropFirst("--script=".count))
        let child = ManagedProcess()
        let result: String = await withCheckedContinuation { continuation in
            var output = Data()
            child.start(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", command], input: Data(), environment: SecureRuntime.environment,
                        started: {}, stdout: { output.append($0) }, stderr: { _ in },
                        exited: { _ in continuation.resume(returning: String(decoding: output, as: UTF8.self)) },
                        failed: { continuation.resume(returning: $0) })
        }
        #expect(result == "quoted-path-ok")
    }

    @Test func runningChildStopsWithoutBlockingMainActor() async {
        let child = ManagedProcess()
        let status: Int32 = await withCheckedContinuation { continuation in
            child.start(executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["30"], input: Data(), environment: SecureRuntime.environment,
                        started: { child.stop() }, stdout: { _ in }, stderr: { _ in },
                        exited: { continuation.resume(returning: $0) },
                        failed: { _ in continuation.resume(returning: -1) })
        }
        #expect(status == SIGTERM)
    }

    @Test func streamedOutputArrivesBeforeExit() async {
        let startedAt = Date()
        let child = ManagedProcess()
        let result: String = await withCheckedContinuation { continuation in
            var output = Data()
            child.start(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "printf streaming; exec /bin/sleep 30"], input: Data(), environment: SecureRuntime.environment,
                        started: {}, stdout: { output.append($0); child.stop() }, stderr: { _ in },
                        exited: { _ in continuation.resume(returning: String(decoding: output, as: UTF8.self)) },
                        failed: { continuation.resume(returning: $0) })
        }
        #expect(result == "streaming")
        #expect(Date().timeIntervalSince(startedAt) < 3, "Short progress messages must arrive before the sleeping process exits")
    }

    @Test func closedChildStdinDoesNotTerminateTheParent() async {
        let child = ManagedProcess()
        let result: String = await withCheckedContinuation { continuation in
            var output = Data()
            child.start(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "exec 0<&-; printf alive; /bin/sleep 0.05"], input: Data(repeating: 65, count: 1_048_576), environment: SecureRuntime.environment,
                        started: {}, stdout: { output.append($0) }, stderr: { _ in },
                        exited: { _ in continuation.resume(returning: String(decoding: output, as: UTF8.self)) },
                        failed: { continuation.resume(returning: $0) })
        }
        #expect(result == "alive")
    }

    @Test func sigtermIgnoringProcessAndLeakedPipeDescriptorAreBoundedAndReportedOnce() async throws {
        // Main process ignores SIGTERM, spawns a grandchild that holds stdout/stderr open for 30s, then sleeps.
        let pidFile = FileManager.default.temporaryDirectory.appendingPathComponent("leaked-\(UUID().uuidString).pid")
        defer {
            if let text = try? String(contentsOf: pidFile, encoding: .utf8),
               let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 {
                kill(pid, SIGKILL)
            }
            try? FileManager.default.removeItem(at: pidFile)
        }

        let managed = ManagedProcess(gracefulTimeout: 0.2, scriptKillGrace: 0.1, logDrainTimeout: 0.25)
        let startedAt = Date()
        var callbackCount = 0

        let outcome: VPNExitOutcome = await withCheckedContinuation { continuation in
            let script = """
            trap '' TERM
            /bin/sleep 30 &
            echo $! > '\(pidFile.path)'
            printf 'ready\\n'
            /bin/sleep 30
            """
            managed.startWithOutcome(
                executable: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", script],
                input: Data(),
                environment: SecureRuntime.environment,
                started: {},
                stdout: { data in
                    if String(decoding: data, as: UTF8.self).contains("ready") {
                        managed.stop()
                    }
                },
                stderr: { _ in },
                exited: { result in
                    callbackCount += 1
                    if callbackCount == 1 {
                        continuation.resume(returning: result)
                    }
                },
                failed: { _ in
                    continuation.resume(returning: VPNExitOutcome(status: -1, processConfirmedStopped: false))
                }
            )
        }

        let elapsed = Date().timeIntervalSince(startedAt)
        #expect(elapsed < 3.0)
        #expect(callbackCount == 1)
        #expect(outcome.processConfirmedStopped)
        #expect(outcome.wasForceKilled)
        #expect(!outcome.logsComplete)
        #expect(!outcome.networkCleanupComplete)
    }

    @Test func hungIndependentProcessGroupScriptIsTerminatedWithoutAffectingOtherSession() async throws {
        let tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent("script-lifecycle-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        // Spawn an unrelated helper child representing another session B so we can verify it is untouched.
        let otherSessionProcess = Process()
        otherSessionProcess.executableURL = URL(fileURLWithPath: "/bin/sleep")
        otherSessionProcess.arguments = ["30"]
        try otherSessionProcess.run()
        let otherPID = otherSessionProcess.processIdentifier
        defer {
            if otherSessionProcess.isRunning { otherSessionProcess.terminate() }
        }

        // Session A simulates an OpenConnect disconnect script in its own process group that ignores SIGTERM and hangs.
        let sessionAID = UUID().uuidString
        let stateDirA = tempRoot.appendingPathComponent(sessionAID, isDirectory: true)
        let scriptPidFile = tempRoot.appendingPathComponent("hung-script.pid")

        let managedA = ManagedProcess(
            sessionID: sessionAID,
            stateDirectory: stateDirA,
            gracefulTimeout: 0.25,
            scriptKillGrace: 0.15,
            logDrainTimeout: 0.2,
            scriptTimeout: 0.5
        )

        // The main process spawns an independent process-group script that writes a VPNScriptLease for session A and ignores TERM.
        let pythonOrPerlSpawn = """
        /usr/bin/python3 -c '
        import json, os, signal, subprocess, time
        os.makedirs(os.environ["OCGUI_STATE_DIR"], exist_ok=True)
        with open(os.path.join(os.environ["OCGUI_STATE_DIR"], "disconnect-started"), "w") as f:
            f.write("1")
        proc = subprocess.Popen(
            ["/bin/sh", "-c", "trap \\"\\" TERM; /bin/sleep 30"],
            preexec_fn=os.setsid,
            close_fds=True
        )
        with open("\(scriptPidFile.path)", "w") as f:
            f.write(str(proc.pid))
        lease = {
            "sessionID": os.environ["OCGUI_SESSION_ID"],
            "runnerPID": proc.pid,
            "pgid": proc.pid,
            "parentPID": os.getpid(),
            "reason": "disconnect",
            "startTimeSec": 0
        }
        with open(os.path.join(os.environ["OCGUI_STATE_DIR"], f"lease-{proc.pid}.json"), "w") as f:
            json.dump(lease, f)
        print("script-spawned", flush=True)
        '
        """

        let outcome: VPNExitOutcome = await withCheckedContinuation { continuation in
            var env = SecureRuntime.environment
            env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
            managedA.startWithOutcome(
                executable: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", pythonOrPerlSpawn],
                input: Data(),
                environment: env,
                started: {},
                stdout: { _ in },
                stderr: { _ in },
                exited: { continuation.resume(returning: $0) },
                failed: { _ in continuation.resume(returning: VPNExitOutcome(status: -1, processConfirmedStopped: false)) }
            )
        }

        let hungPIDText = try String(contentsOf: scriptPidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let hungPID = try #require(Int32(hungPIDText))

        // Wait briefly for kernel reap if needed, then verify the hung script PGID was killed while otherSessionProcess is still alive!
        for _ in 0..<10 where kill(hungPID, 0) == 0 {
            try await Task.sleep(for: .milliseconds(30))
        }
        #expect(kill(hungPID, 0) != 0)
        #expect(otherSessionProcess.isRunning)
        #expect(kill(otherPID, 0) == 0)
        #expect(outcome.processConfirmedStopped)
        #expect(outcome.wasForceKilled)
        #expect(!outcome.networkCleanupComplete)
    }

    @Test func fixedScriptRunnerEnforcesTimeoutAndRecordsDisconnectCompletion() async throws {
        let tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent("runner-direct-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        // 1. Normal disconnect script completes within deadline and writes disconnect-completed marker.
        let okScript = tempRoot.appendingPathComponent("vpnc-ok.sh")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: okScript)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: okScript.path)
        let okStateDir = tempRoot.appendingPathComponent("ok-state", isDirectory: true)
        let okStatus = VPNScriptRunner.executeFixedScript(
            scriptURL: okScript,
            environment: [
                VPNScriptRunner.sessionIDEnv: UUID().uuidString,
                VPNScriptRunner.stateDirEnv: okStateDir.path,
                VPNScriptRunner.scriptTimeoutEnv: "2.0",
                "reason": "disconnect"
            ]
        )
        #expect(okStatus == 0)
        #expect(FileManager.default.fileExists(atPath: okStateDir.appendingPathComponent("disconnect-completed").path))

        // 2. Hung script exceeding OCGUI_SCRIPT_TIMEOUT is killed along with its process group and returns 124.
        let hungChildPidFile = tempRoot.appendingPathComponent("runner-child.pid")
        let hungScript = tempRoot.appendingPathComponent("vpnc-hung.sh")
        try Data("""
        #!/bin/sh
        trap '' TERM
        /bin/sleep 30 &
        echo $! > '\(hungChildPidFile.path)'
        /bin/sleep 30
        """.utf8).write(to: hungScript)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: hungScript.path)
        let hungStateDir = tempRoot.appendingPathComponent("hung-state", isDirectory: true)
        let timeoutStatus = VPNScriptRunner.executeFixedScript(
            scriptURL: hungScript,
            environment: [
                VPNScriptRunner.sessionIDEnv: UUID().uuidString,
                VPNScriptRunner.stateDirEnv: hungStateDir.path,
                VPNScriptRunner.scriptTimeoutEnv: "0.25",
                VPNScriptRunner.parentCheckIntervalEnv: "20",
                "reason": "disconnect"
            ]
        )
        #expect(timeoutStatus == 124)
        #expect(FileManager.default.fileExists(atPath: hungStateDir.appendingPathComponent("script-forced-termination").path))
        if let pidText = try? String(contentsOf: hungChildPidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           let childPID = Int32(pidText) {
            for _ in 0..<10 where kill(childPID, 0) == 0 {
                try await Task.sleep(for: .milliseconds(25))
            }
            #expect(kill(childPID, 0) != 0)
        }
    }

    @Test func runtimeComparisonVerifiesManifestAndDylibsAndCABundleMergesEnterpriseCerts() throws {
        let tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent("runtime-verify-\(UUID().uuidString)", isDirectory: true)
        let bundledRuntime = tempRoot.appendingPathComponent("bundled/OpenConnect", isDirectory: true)
        let installedRuntime = tempRoot.appendingPathComponent("installed/OpenConnect", isDirectory: true)
        let bundledHelper = tempRoot.appendingPathComponent("bundled/OpenConnectHelper")
        let installedHelper = tempRoot.appendingPathComponent("installed/OpenConnectHelper")
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        for root in [bundledRuntime, installedRuntime] {
            try FileManager.default.createDirectory(at: root.appendingPathComponent("bin"), withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: root.appendingPathComponent("lib"), withIntermediateDirectories: true)
            try Data("binary".utf8).write(to: root.appendingPathComponent("bin/openconnect"))
            try Data("script".utf8).write(to: root.appendingPathComponent("vpnc-script"))
            try Data("-----BEGIN CERTIFICATE-----\nBASE\n-----END CERTIFICATE-----\n".utf8).write(to: root.appendingPathComponent("ca-bundle.pem"))
            try Data("{\"version\":1}".utf8).write(to: root.appendingPathComponent("build-manifest.json"))
            try Data("dylib-v1".utf8).write(to: root.appendingPathComponent("lib/libopenconnect.5.dylib"))
        }
        try Data("helper".utf8).write(to: bundledHelper)
        try Data("helper".utf8).write(to: installedHelper)

        #expect(HelperVPNTransport.isInstalledRuntimeMatchingBundle(
            bundledRuntime: bundledRuntime,
            bundledHelper: bundledHelper,
            installedRuntime: installedRuntime,
            installedHelper: installedHelper,
            requireAuthorizedCaller: false
        ))

        // Corrupt a dylib in installed runtime -> must detect mismatch.
        try Data("dylib-v2".utf8).write(to: installedRuntime.appendingPathComponent("lib/libopenconnect.5.dylib"))
        #expect(!HelperVPNTransport.isInstalledRuntimeMatchingBundle(
            bundledRuntime: bundledRuntime,
            bundledHelper: bundledHelper,
            installedRuntime: installedRuntime,
            installedHelper: installedHelper,
            requireAuthorizedCaller: false
        ))

        // Test CA bundle merging with custom enterprise certificate PEM.
        let baseCA = bundledRuntime.appendingPathComponent("ca-bundle.pem")
        let customPEM = "-----BEGIN CERTIFICATE-----\nENTERPRISE_CA\n-----END CERTIFICATE-----\n"
        let mergedPath = HelperVPNTransport.effectiveCABundlePath(
            baseCABundle: baseCA,
            systemKeychainPath: "/nonexistent/System.keychain",
            customCertificatesPEM: customPEM
        )
        let mergedContent = try String(contentsOfFile: mergedPath, encoding: .utf8)
        #expect(mergedContent.contains("BASE"))
        #expect(mergedContent.contains("ENTERPRISE_CA"))

        // Test uppercase HTTPS:// scheme and bare IPv6 literal normalization.
        let upperConfig = VPNConfiguration(
            name: "Upper",
            serverAddress: "HTTPS://vpn.example.com:8443/ group",
            username: "user",
            rememberCredentials: true
        )
        #expect(upperConfig.normalizedServer.hasPrefix("https://"))
        #expect(TunnelRequest.validServer("HTTPS://vpn.example.com:8443"))

        let ipv6Auth = try AuthenticationResult(data: Data("""
        COOKIE='secret-cookie'
        HOST='2001:db8::1'
        FINGERPRINT='pin-sha256:AbCdEf123456='
        """.utf8))
        let ipv6Req = try ipv6Auth.request(protocolType: "anyconnect", originalServer: "https://vpn.example.com")
        #expect(ipv6Req.server == "https://[2001:db8::1]")
    }

    @Test func smartEndpointResolverFiltersFakeIPsAndPrefersDirectIPv4() throws {
        // 1. Fake-IP (198.18.0.0/15) vs real public IPv4 classification
        #expect(VPNEndpointResolver.isFakeOrUnusableIPv4("198.18.0.1"))
        #expect(VPNEndpointResolver.isFakeOrUnusableIPv4("198.18.6.78"))
        #expect(VPNEndpointResolver.isFakeOrUnusableIPv4("198.19.255.254"))
        #expect(VPNEndpointResolver.isFakeOrUnusableIPv4("127.0.0.1"))
        #expect(!VPNEndpointResolver.isFakeOrUnusableIPv4("1.13.176.57"))
        #expect(!VPNEndpointResolver.isFakeOrUnusableIPv4("198.20.1.1"))

        // 2. Physical default route extraction ignores utun interfaces
        let sampleNetstat = """
        Routing tables
        Internet:
        Destination        Gateway            Flags               Netif Expire
        default            198.18.0.1         UGSc                utun6
        default            10.52.48.1         UGScg                 en0
        1                  198.18.0.1         UGSc                utun6
        """
        let route = VPNEndpointResolver.parsePhysicalDefaultRoute(from: sampleNetstat)
        #expect(route?.interfaceName == "en0")
        #expect(route?.gatewayIPv4 == "10.52.48.1")

        // 3. DNS wire-format query & response parsing filters Fake-IP and extracts real IPv4
        let query = try #require(VPNEndpointResolver.buildDNSQuery(host: "ywl.anylink.pub", qtype: 1, txid: 0x4242))
        var response = Data()
        response.append(contentsOf: [0x42, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        response.append(query.dropFirst(12))
        // Answer 1: Fake-IP 198.18.6.78 (must be filtered out)
        response.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 198, 18, 6, 78])
        // Answer 2: Real IPv4 1.13.176.57 (must be retained)
        response.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 13, 176, 57])
        let parsedIPs = VPNEndpointResolver.parseDNSResponse(response, expectedTxid: 0x4242, expectedQType: 1)
        #expect(parsedIPs == ["1.13.176.57"])

        // 4. AuthenticationResult replaces slower IPv6 or Fake-IP RESOLVE with verified preferredResolve
        let authWithIPv6 = try AuthenticationResult(data: Data("""
        COOKIE='secret-cookie'
        HOST='https://ywl.anylink.pub:22877/'
        FINGERPRINT='pin-sha256:wKhQo3FVIHWQIOmJI0pLRNwjZYskw44jd7slr+XW4qg='
        RESOLVE='ywl.anylink.pub:2402:4e00:c021:1900:22b6:7560:a232:1'
        """.utf8))
        let tunnelReq = try authWithIPv6.request(
            protocolType: "anyconnect",
            originalServer: "https://ywl.anylink.pub:22877",
            preferredResolve: "ywl.anylink.pub:1.13.176.57"
        )
        #expect(tunnelReq.resolve == "ywl.anylink.pub:1.13.176.57")
        #expect(VPNEndpointResolver.extractGatewayIP(from: tunnelReq) == "1.13.176.57")
    }
}
