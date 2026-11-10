import Foundation
import CryptoKit
import IOKit
import Security

struct StoredCredential: Codable, Equatable, Sendable {
    let credentialID: UUID
    let binding: CredentialBinding
    let password: String
}

struct EncryptedStoredCredential: Codable, Equatable, Sendable {
    let credentialID: UUID
    let binding: CredentialBinding
    let sealedPassword: Data
}

protocol VPNPasswordStore {
    func load(credentialID: UUID, expected: CredentialBinding) -> String?
    func save(_ password: String, credentialID: UUID, binding: CredentialBinding, label: String) throws
    func delete(credentialID: UUID) throws
    func allCredentialIDs() throws -> Set<UUID>
    func loadLegacy(for config: VPNConfiguration, migrationVersion: Int) throws -> String?
    func deleteLegacyV1(for profileID: UUID) throws
}

extension VPNPasswordStore {
    func load(for config: VPNConfiguration) -> String? {
        guard config.rememberCredentials, let credentialID = config.credentialID else { return nil }
        return load(credentialID: credentialID, expected: config.credentialBinding)
    }

    func allCredentialIDs() throws -> Set<UUID> { [] }
    func loadLegacy(for config: VPNConfiguration, migrationVersion: Int) throws -> String? { nil }
    func deleteLegacyV1(for profileID: UUID) throws {}
}

struct SystemVPNPasswordStore: VPNPasswordStore {
    func load(credentialID: UUID, expected: CredentialBinding) -> String? {
        KeychainService.loadPassword(credentialID: credentialID, expected: expected)
    }

    func save(_ password: String, credentialID: UUID, binding: CredentialBinding, label: String) throws {
        try KeychainService.savePassword(password, credentialID: credentialID, binding: binding, label: label)
    }

    func delete(credentialID: UUID) throws {
        try KeychainService.deletePassword(credentialID: credentialID)
    }

    func allCredentialIDs() throws -> Set<UUID> {
        try KeychainService.allCredentialIDs()
    }

    func loadLegacy(for config: VPNConfiguration, migrationVersion: Int) throws -> String? {
        try KeychainService.loadLegacyPassword(for: config, migrationVersion: migrationVersion)
    }

    func deleteLegacyV1(for profileID: UUID) throws {
        try KeychainService.deleteLegacyV1Password(for: profileID)
    }
}

enum KeychainService {
    static let credentialService = "mjucha.OpenconnectGUI.credential.v2"
    static let legacyV1Service = "mjucha.OpenconnectGUI.profile-password"
    private static let lock = NSLock()

    private static var localStoreDirectoryURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support", isDirectory: true)
        return base.appendingPathComponent("OpenConnectGUI", isDirectory: true)
    }

    private static var localStoreURL: URL {
        localStoreDirectoryURL.appendingPathComponent("credentials.v2.json")
    }

    private static var localKeyURL: URL {
        localStoreDirectoryURL.appendingPathComponent(".vault.key")
    }

    private static func machineHardwareIdentity() -> Data {
        var identity = "uid:\(getuid());".data(using: .utf8) ?? Data()
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if service != IO_OBJECT_NULL {
            defer { IOObjectRelease(service) }
            if let uuidCF = IORegistryEntryCreateCFProperty(service, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String {
                identity.append(Data(uuidCF.utf8))
            }
        }
        return identity
    }

    private static func loadOrCreateMasterSeedUnlocked(at keyURL: URL) throws -> Data {
        if let existing = try? Data(contentsOf: keyURL), existing.count == 32 {
            return existing
        }
        let dir = keyURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let newKey = SymmetricKey(size: .bits256)
        let seed = newKey.withUnsafeBytes { Data($0) }
        try seed.write(to: keyURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        _ = chflags(keyURL.path, u_int(UF_HIDDEN))
        return seed
    }

    private static func authenticatedBindingData(credentialID: UUID, binding: CredentialBinding) -> Data {
        let raw = "\(credentialID.uuidString)|\(binding.profileID.uuidString)|\(binding.server)|\(binding.username)|\(binding.protocolType)"
        return Data(raw.utf8)
    }

    private static func deriveKeyUnlocked(credentialID: UUID, binding: CredentialBinding, keyURL: URL) throws -> SymmetricKey {
        let seed = try loadOrCreateMasterSeedUnlocked(at: keyURL)
        let ikm = SymmetricKey(data: seed)
        let salt = machineHardwareIdentity()
        let info = authenticatedBindingData(credentialID: credentialID, binding: binding)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

    static func sealPassword(
        _ password: String,
        credentialID: UUID,
        binding: CredentialBinding,
        keyURL: URL = localKeyURL
    ) throws -> EncryptedStoredCredential {
        let key = try deriveKeyUnlocked(credentialID: credentialID, binding: binding, keyURL: keyURL)
        let aad = authenticatedBindingData(credentialID: credentialID, binding: binding)
        let box = try AES.GCM.seal(Data(password.utf8), using: key, authenticating: aad)
        guard let combined = box.combined else {
            throw VPNServiceError.message("Could not encrypt VPN credential.")
        }
        return EncryptedStoredCredential(
            credentialID: credentialID,
            binding: binding,
            sealedPassword: combined
        )
    }

    static func openPassword(
        _ record: EncryptedStoredCredential,
        expectedID: UUID,
        expectedBinding: CredentialBinding,
        keyURL: URL = localKeyURL
    ) -> String? {
        guard record.credentialID == expectedID,
              record.binding == expectedBinding else {
            return nil
        }
        guard let key = try? deriveKeyUnlocked(credentialID: expectedID, binding: expectedBinding, keyURL: keyURL),
              let box = try? AES.GCM.SealedBox(combined: record.sealedPassword) else {
            return nil
        }
        let aad = authenticatedBindingData(credentialID: expectedID, binding: expectedBinding)
        guard let decrypted = try? AES.GCM.open(box, using: key, authenticating: aad),
              let password = String(data: decrypted, encoding: .utf8),
              !password.isEmpty else {
            return nil
        }
        return password
    }

    static func readLocalStoreUnlocked(
        storeURL: URL = localStoreURL,
        keyURL: URL = localKeyURL
    ) -> [String: EncryptedStoredCredential] {
        guard let data = try? Data(contentsOf: storeURL) else {
            return [:]
        }
        if let encrypted = try? JSONDecoder().decode([String: EncryptedStoredCredential].self, from: data) {
            return encrypted
        }
        // Automatically migrate legacy plaintext StoredCredential JSON to AES-GCM encrypted records.
        if let legacyPlaintext = try? JSONDecoder().decode([String: StoredCredential].self, from: data) {
            var migrated: [String: EncryptedStoredCredential] = [:]
            for (key, item) in legacyPlaintext {
                if let sealed = try? sealPassword(
                    item.password,
                    credentialID: item.credentialID,
                    binding: item.binding,
                    keyURL: keyURL
                ) {
                    migrated[key] = sealed
                }
            }
            try? writeLocalStoreUnlocked(migrated, storeURL: storeURL)
            return migrated
        }
        return [:]
    }

    static func writeLocalStoreUnlocked(
        _ items: [String: EncryptedStoredCredential],
        storeURL: URL = localStoreURL
    ) throws {
        let dir = storeURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let data = try JSONEncoder().encode(items)
        try data.write(to: storeURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storeURL.path)
    }

    private static func legacyV1Query(for profileID: UUID) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyV1Service,
            kSecAttrAccount as String: profileID.uuidString
        ]
    }

    static func savePassword(_ password: String, credentialID: UUID, binding: CredentialBinding, label: String) throws {
        lock.lock()
        defer { lock.unlock() }
        let encrypted = try sealPassword(password, credentialID: credentialID, binding: binding)
        var store = readLocalStoreUnlocked()
        store[credentialID.uuidString] = encrypted
        try writeLocalStoreUnlocked(store)
    }

    static func loadPassword(credentialID: UUID, expected: CredentialBinding) -> String? {
        lock.lock()
        let localItem = readLocalStoreUnlocked()[credentialID.uuidString]
        lock.unlock()
        guard let localItem else { return nil }
        return openPassword(localItem, expectedID: credentialID, expectedBinding: expected)
    }

    static func loadPassword(for config: VPNConfiguration) -> String? {
        guard config.rememberCredentials, let credentialID = config.credentialID else { return nil }
        return loadPassword(credentialID: credentialID, expected: config.credentialBinding)
    }

    static func deletePassword(credentialID: UUID) throws {
        lock.lock()
        var store = readLocalStoreUnlocked()
        store.removeValue(forKey: credentialID.uuidString)
        try writeLocalStoreUnlocked(store)
        lock.unlock()
    }

    static func allCredentialIDs() throws -> Set<UUID> {
        lock.lock()
        let keys = Array(readLocalStoreUnlocked().keys)
        lock.unlock()
        return Set(keys.compactMap(UUID.init(uuidString:)))
    }

    /// Reads v1 profile-UUID or v0 Internet Password without deleting shared Internet Password entries.
    static func loadLegacyPassword(for config: VPNConfiguration, migrationVersion: Int) throws -> String? {
        guard config.rememberCredentials else { return nil }
        if let v1Data = try readDataChecked(legacyV1Query(for: config.id)),
           let v1Password = String(data: v1Data, encoding: .utf8),
           !v1Password.isEmpty {
            return v1Password
        }
        guard migrationVersion == 0 else { return nil }
        let legacyV0: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: config.username,
            kSecAttrServer as String: config.serverAddress
        ]
        if let v0Data = try readDataChecked(legacyV0),
           let v0Password = String(data: v0Data, encoding: .utf8),
           !v0Password.isEmpty {
            return v0Password
        }
        return nil
    }

    static func deleteLegacyV1Password(for profileID: UUID) throws {
        let status = SecItemDelete(legacyV1Query(for: profileID) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    private static func readDataChecked(_ query: [String: Any]) throws -> Data? {
        var query = query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        try check(status)
        return value as? Data
    }

    private static func check(_ status: OSStatus) throws {
        guard status != errSecSuccess else { return }
        throw VPNServiceError.message("Keychain: \((SecCopyErrorMessageString(status, nil) as String?) ?? "Operation failed (\(status))")")
    }
}
