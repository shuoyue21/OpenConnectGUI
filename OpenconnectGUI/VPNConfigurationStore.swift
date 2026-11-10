import Foundation
import Combine

@MainActor
final class VPNConfigurationStore: ObservableObject {
    @Published private(set) var configurations: [VPNConfiguration] = []
    @Published var errorMessage: String?
    @Published var requestedConnectConfig: VPNConfiguration?
    @Published private(set) var pendingCleanupCredentialIDs: Set<UUID> = []

    let connections: ConnectionStore
    private let configFileURL: URL
    private let passwords: VPNPasswordStore
    private let fileWriter: (Data, URL) throws -> Void
    private let cleanupRetryDelay: TimeInterval
    private var cleanupRetryTask: Task<Void, Never>?
    private(set) var loadFailed = false

    init(
        configFileURL: URL? = nil,
        passwords: VPNPasswordStore = SystemVPNPasswordStore(),
        connections: ConnectionStore? = nil,
        cleanupRetryDelay: TimeInterval = 2.0,
        fileWriter: @escaping (Data, URL) throws -> Void = { data, url in
            try data.write(to: url, options: .atomic)
        }
    ) {
        self.passwords = passwords
        self.connections = connections ?? ConnectionStore()
        self.cleanupRetryDelay = cleanupRetryDelay
        self.fileWriter = fileWriter
        self.configFileURL = configFileURL ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("OpenConnectGUI/vpn_configurations.json")

        do {
            if FileManager.default.fileExists(atPath: self.configFileURL.path) {
                var configs = try JSONDecoder().decode([VPNConfiguration].self, from: Data(contentsOf: self.configFileURL))
                guard Set(configs.map(\.id)).count == configs.count else {
                    throw VPNServiceError.message("Duplicate VPN configuration identifiers.")
                }

                // Migrate legacy credentials using versioned credentialID commit order.
                var migrated = false
                var newlyCreatedIDs: [UUID] = []
                var migratedProfileIDs: [UUID] = []

                do {
                    for index in configs.indices {
                        let currentVersion = configs[index].credentialMigrationVersion
                        let needsVersionUpgrade = currentVersion < VPNConfiguration.currentCredentialMigrationVersion
                        let needsCredentialIDMigration = configs[index].rememberCredentials && configs[index].credentialID == nil && currentVersion < VPNConfiguration.currentCredentialMigrationVersion

                        if needsVersionUpgrade || needsCredentialIDMigration {
                            if configs[index].rememberCredentials {
                                if configs[index].credentialID == nil,
                                   let legacyPassword = try passwords.loadLegacy(for: configs[index], migrationVersion: currentVersion),
                                   !legacyPassword.isEmpty {
                                    let newID = UUID()
                                    try passwords.save(
                                        legacyPassword,
                                        credentialID: newID,
                                        binding: configs[index].credentialBinding,
                                        label: configs[index].name
                                    )
                                    newlyCreatedIDs.append(newID)
                                    configs[index].credentialID = newID
                                    migratedProfileIDs.append(configs[index].id)
                                }
                            } else {
                                configs[index].credentialID = nil
                            }
                            configs[index].credentialMigrationVersion = VPNConfiguration.currentCredentialMigrationVersion
                            migrated = true
                        }
                    }

                    if migrated {
                        try persist(configs)
                    }
                } catch {
                    // Roll back newly created Keychain items if migration or file persistence failed.
                    for id in newlyCreatedIDs {
                        try? passwords.delete(credentialID: id)
                    }
                    throw error
                }

                // Clean up obsolete v1 profile-keyed entries only after new versioned credentials are committed.
                for profileID in migratedProfileIDs {
                    try? passwords.deleteLegacyV1(for: profileID)
                }

                configs.forEach { self.connections.register($0) }
                configurations = configs
            }
            // Only clean up orphaned credentials when configuration loading succeeded.
            cleanupOrphanedCredentials()
        } catch {
            loadFailed = configurations.isEmpty
            errorMessage = "Could not load VPN configurations or credentials: \(error.localizedDescription)"
        }
    }

    deinit {
        cleanupRetryTask?.cancel()
    }

    func savedPassword(for config: VPNConfiguration) -> String? {
        guard let current = configurations.first(where: { $0.id == config.id }) ?? Optional(config) else {
            return nil
        }
        return passwords.load(for: current)
    }

    func add(_ config: VPNConfiguration, password: String? = nil) throws {
        try validate(config)
        guard !configurations.contains(where: { $0.id == config.id }) else {
            throw VPNServiceError.message("This VPN configuration already exists.")
        }

        var toSave = config
        toSave.credentialMigrationVersion = VPNConfiguration.currentCredentialMigrationVersion
        let explicitPassword = password.flatMap { $0.isEmpty ? nil : $0 }
        var createdCredentialID: UUID?

        if toSave.rememberCredentials, let explicitPassword {
            try validatePassword(explicitPassword)
            let newID = UUID()
            try passwords.save(
                explicitPassword,
                credentialID: newID,
                binding: toSave.credentialBinding,
                label: toSave.name
            )
            createdCredentialID = newID
            toSave.credentialID = newID
        } else {
            toSave.credentialID = nil
        }

        let updated = configurations + [toSave]
        do {
            try persist(updated)
        } catch {
            if let createdCredentialID {
                try? passwords.delete(credentialID: createdCredentialID)
            }
            throw error
        }

        connections.register(toSave)
        configurations = updated
    }

    func update(_ config: VPNConfiguration, password: String? = nil) throws {
        try validate(config)
        guard let index = configurations.firstIndex(where: { $0.id == config.id }) else { return }
        let old = configurations[index]
        let identityChanged = !old.hasSameIdentity(as: config)
        let explicitPassword = password.flatMap { $0.isEmpty ? nil : $0 }

        var toSave = config
        toSave.credentialMigrationVersion = VPNConfiguration.currentCredentialMigrationVersion
        let oldCredentialID = old.credentialID
        var newlyCreatedCredentialID: UUID?
        var credentialToRetireAfterCommit: UUID?

        if !toSave.rememberCredentials {
            // Turning off Remember Credentials: commit configuration with nil credentialID first, then delete old Keychain item.
            toSave.credentialID = nil
            credentialToRetireAfterCommit = oldCredentialID
        } else if let explicitPassword {
            // New password provided: create a new versioned Keychain item while keeping the old one until file commit succeeds.
            try validatePassword(explicitPassword)
            let newID = UUID()
            try passwords.save(
                explicitPassword,
                credentialID: newID,
                binding: toSave.credentialBinding,
                label: toSave.name
            )
            newlyCreatedCredentialID = newID
            toSave.credentialID = newID
            credentialToRetireAfterCommit = oldCredentialID
        } else if identityChanged {
            // Identity changed without a new password: never bind old password to a new server/user/protocol.
            toSave.credentialID = nil
            credentialToRetireAfterCommit = oldCredentialID
        } else {
            // Same identity, no new password typed: preserve valid bound credential reference if it still matches.
            if let existingID = oldCredentialID,
               passwords.load(credentialID: existingID, expected: toSave.credentialBinding) != nil {
                toSave.credentialID = existingID
            } else {
                toSave.credentialID = nil
            }
        }

        var updated = configurations
        updated[index] = toSave

        do {
            try persist(updated)
        } catch {
            if let newlyCreatedCredentialID {
                try? passwords.delete(credentialID: newlyCreatedCredentialID)
            }
            throw error
        }

        // Publish updated configuration and update connection state / reconnect cache.
        connections.register(toSave)
        if identityChanged || explicitPassword != nil || !toSave.rememberCredentials {
            if explicitPassword != nil {
                connections.credentialsChanged(for: toSave, password: explicitPassword)
            } else {
                connections.credentialsChanged(for: toSave, password: nil)
            }
        }
        configurations = updated

        // Clean up retired credential after configuration commit.
        if let retiredID = credentialToRetireAfterCommit, retiredID != toSave.credentialID {
            retireCredential(retiredID, turningOffRemember: !toSave.rememberCredentials)
        }
    }

    /// Credential persistence and the session cache are updated together before connecting.
    func prepareConnection(_ config: VPNConfiguration, password: String, remember: Bool) throws {
        var updated = config
        updated.rememberCredentials = remember
        try update(updated, password: remember ? password : nil)
        if !remember {
            connections.credentialsChanged(for: updated, password: password)
        }
    }

    func remove(_ config: VPNConfiguration) throws {
        guard let current = configurations.first(where: { $0.id == config.id }) else { return }
        if let state = connections.connection(for: current),
           state.hasUnfinishedProcess || state.isReconnecting || state.isWaitingForNetwork || state.isRecoveringConnection {
            if state.hasUnfinishedProcess {
                // Keep the entry while disconnecting; only commit deletion once stop is confirmed.
                state.isPendingDeletion = true
                state.disconnect { [weak self] cleanlyStopped in
                    guard let self else { return }
                    guard cleanlyStopped, !state.hasUnfinishedProcess else {
                        state.isPendingDeletion = false
                        self.errorMessage = "Could not delete '\(current.name)' because disconnecting or network cleanup failed. Resolve the connection state and try again."
                        return
                    }
                    do {
                        try self.commitRemoval(id: current.id)
                    } catch {
                        state.isPendingDeletion = false
                        self.errorMessage = error.localizedDescription
                    }
                }
                return
            } else {
                state.disconnect()
            }
        }
        try commitRemoval(id: current.id)
    }

    private func commitRemoval(id: UUID) throws {
        guard let current = configurations.first(where: { $0.id == id }) else { return }
        let updated = configurations.filter { $0.id != id }
        try persist(updated)
        connections.remove(current)
        configurations = updated
        if let credentialID = current.credentialID {
            retireCredential(credentialID, turningOffRemember: false)
        }
    }

    private func retireCredential(_ credentialID: UUID, turningOffRemember: Bool) {
        do {
            try passwords.delete(credentialID: credentialID)
            pendingCleanupCredentialIDs.remove(credentialID)
        } catch {
            pendingCleanupCredentialIDs.insert(credentialID)
            if turningOffRemember {
                errorMessage = "Configuration was saved, but the previous saved credential has not been deleted yet. Cleanup will be retried."
            } else {
                errorMessage = "Changes were saved, but an old credential could not be deleted from local encrypted storage yet. Cleanup will be retried."
            }
            scheduleCredentialCleanupRetry()
        }
    }

    private func scheduleCredentialCleanupRetry() {
        cleanupRetryTask?.cancel()
        let delay = cleanupRetryDelay
        cleanupRetryTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) } catch { return }
            guard let self else { return }
            self.retryPendingCredentialDeletions()
        }
    }

    func retryPendingCredentialDeletions() {
        let referenced = Set(configurations.compactMap(\.credentialID))
        for id in Array(pendingCleanupCredentialIDs) {
            if referenced.contains(id) {
                pendingCleanupCredentialIDs.remove(id)
                continue
            }
            if (try? passwords.delete(credentialID: id)) != nil {
                pendingCleanupCredentialIDs.remove(id)
            }
        }
        if !pendingCleanupCredentialIDs.isEmpty {
            scheduleCredentialCleanupRetry()
        }
    }

    /// Removes orphaned credentials in the v2 credential namespace that are not referenced by any committed profile.
    func cleanupOrphanedCredentials() {
        guard !loadFailed else { return }
        guard let storedIDs = try? passwords.allCredentialIDs() else { return }
        let referencedIDs = Set(configurations.compactMap(\.credentialID))
        for id in storedIDs where !referencedIDs.contains(id) {
            do {
                try passwords.delete(credentialID: id)
            } catch {
                pendingCleanupCredentialIDs.insert(id)
            }
        }
        if !pendingCleanupCredentialIDs.isEmpty {
            scheduleCredentialCleanupRetry()
        }
    }

    private func persist(_ configs: [VPNConfiguration]) throws {
        guard !loadFailed else {
            throw VPNServiceError.message("Repair the configuration file before saving; existing data has been preserved.")
        }
        try FileManager.default.createDirectory(
            at: configFileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let data = try JSONEncoder().encode(configs)
        try fileWriter(data, configFileURL)
    }

    private func validatePassword(_ password: String) throws {
        guard !password.isEmpty, !password.contains(where: { $0.isNewline || $0 == "\0" }) else {
            throw VPNServiceError.message("Enter a valid VPN password.")
        }
    }

    private func validate(_ config: VPNConfiguration) throws {
        guard !config.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !config.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !config.username.contains("\0"),
              config.trimmedAuthGroup?.contains(where: { $0.isNewline || $0 == "\0" }) != true,
              TunnelRequest.validServer(config.normalizedServer),
              TunnelRequest.protocols.contains(config.effectiveProtocol) else {
            throw VPNServiceError.message("Enter a connection name, username, valid HTTPS server and supported protocol.")
        }
    }
}
