//
//  VPNConfiguration.swift
//  OpenconnectGUI
//
//  Created by Mikołaj Jucha on 23/04/2025.
//
import Foundation

struct CredentialBinding: Codable, Equatable, Sendable {
    let profileID: UUID
    let server: String
    let username: String
    let protocolType: String
}

/// Represents a single VPN configuration used by the application.
struct VPNConfiguration: Identifiable, Codable, Equatable, Sendable {
    static let currentCredentialMigrationVersion = 2

    /// A unique identifier for the VPN configuration.
    var id: UUID = UUID()
    
    /// A human-readable name for the configuration (displayed in the UI).
    var name: String
    
    /// The VPN server address (e.g., "https://vpn.example.com").
    var serverAddress: String
    
    /// The username used for VPN authentication.
    var username: String

    /// Optional VPN protocol type (e.g., "anyconnect", "gp", "nc", "pulse", "fortinet").
    var protocolType: String?

    /// Optional authentication group (--authgroup) for gateways offering multiple user groups.
    var authGroup: String? = nil

    var trimmedAuthGroup: String? {
        guard let raw = authGroup?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        return raw
    }

    var effectiveProtocol: String {
        let trimmed = (protocolType ?? "anyconnect").trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "anyconnect" : trimmed
    }

    var normalizedServer: String {
        TunnelRequest.normalizeServer(serverAddress)
    }

    /// Indicates whether to store credentials securely in the Keychain.
    var rememberCredentials: Bool

    /// Indicates whether to automatically reconnect when network connectivity is restored.
    var autoReconnect: Bool = false

    /// Versioned reference to the currently bound Keychain item.
    var credentialID: UUID? = nil

    /// Explicit migration version preventing previously forgotten credentials from being re-imported.
    var credentialMigrationVersion: Int = Self.currentCredentialMigrationVersion

    var credentialBinding: CredentialBinding {
        CredentialBinding(
            profileID: id,
            server: normalizedServer,
            username: username,
            protocolType: effectiveProtocol
        )
    }

    func hasSameIdentity(as other: VPNConfiguration) -> Bool {
        normalizedServer == other.normalizedServer &&
        username == other.username &&
        effectiveProtocol == other.effectiveProtocol
    }

    init(
        id: UUID = UUID(),
        name: String,
        serverAddress: String,
        username: String,
        protocolType: String? = "anyconnect",
        authGroup: String? = nil,
        rememberCredentials: Bool,
        autoReconnect: Bool = false,
        credentialID: UUID? = nil,
        credentialMigrationVersion: Int = Self.currentCredentialMigrationVersion
    ) {
        self.id = id
        self.name = name
        self.serverAddress = serverAddress
        self.username = username
        self.protocolType = protocolType
        self.authGroup = authGroup
        self.rememberCredentials = rememberCredentials
        self.autoReconnect = autoReconnect
        self.credentialID = credentialID
        self.credentialMigrationVersion = credentialMigrationVersion
    }

    enum CodingKeys: String, CodingKey {
        case id, name, serverAddress, username, protocolType, authGroup, rememberCredentials, autoReconnect
        case credentialID, credentialMigrationVersion, credentialsMigrated
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        username = try container.decode(String.self, forKey: .username)
        protocolType = try container.decodeIfPresent(String.self, forKey: .protocolType)
        authGroup = try container.decodeIfPresent(String.self, forKey: .authGroup)
        rememberCredentials = try container.decode(Bool.self, forKey: .rememberCredentials)
        autoReconnect = try container.decodeIfPresent(Bool.self, forKey: .autoReconnect) ?? false
        credentialID = try container.decodeIfPresent(UUID.self, forKey: .credentialID)
        if let explicitVersion = try container.decodeIfPresent(Int.self, forKey: .credentialMigrationVersion) {
            credentialMigrationVersion = explicitVersion
        } else if let legacyMigrated = try container.decodeIfPresent(Bool.self, forKey: .credentialsMigrated) {
            credentialMigrationVersion = legacyMigrated ? 1 : 0
        } else {
            credentialMigrationVersion = 0
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(serverAddress, forKey: .serverAddress)
        try container.encode(username, forKey: .username)
        try container.encodeIfPresent(protocolType, forKey: .protocolType)
        try container.encodeIfPresent(trimmedAuthGroup, forKey: .authGroup)
        try container.encode(rememberCredentials, forKey: .rememberCredentials)
        try container.encode(autoReconnect, forKey: .autoReconnect)
        try container.encodeIfPresent(credentialID, forKey: .credentialID)
        try container.encode(credentialMigrationVersion, forKey: .credentialMigrationVersion)
    }
}
