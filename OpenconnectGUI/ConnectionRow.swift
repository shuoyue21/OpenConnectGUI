import SwiftUI

struct ConnectionRow: View {
    let config: VPNConfiguration
    @ObservedObject var connection: VPNConnectionState

    var onConnect: () -> Void
    var onDisconnect: () -> Void
    var onReconnectToApply: (() -> Void)? = nil
    var onSelectGroup: ((String) throws -> Void)? = nil
    var onEdit: () -> Void
    var onShowLogs: () -> Void
    var onDelete: () -> Void

    private var displayedConfig: VPNConfiguration {
        connection.activeConfiguration ?? config
    }

    private var statusText: (String, Color)? {
        if connection.isPendingDeletion {
            return ("Disconnecting before deletion...", .orange)
        } else if connection.isDisconnecting {
            return ("Disconnecting...", .orange)
        } else if connection.isWaitingForNetwork {
            return ("Waiting for network...", .orange)
        } else if connection.isRecoveringConnection {
            return ("Recovering connection...", .orange)
        } else if case .accountLocked = connection.phase {
            return ("Account locked", .red)
        } else if connection.needsCredentials {
            return ("Update credentials", .red)
        } else if connection.isReconnecting && !connection.isConnected {
            return ("Reconnecting...", .orange)
        } else if connection.isConnecting && !connection.isConnected {
            return ("Connecting...", .orange)
        } else if connection.isConnected {
            return ("Connected", .green)
        }
        return nil
    }

    private var hasFailureState: Bool {
        switch connection.phase {
        case .failed, .accountLocked, .needsCredentials:
            return true
        default:
            return false
        }
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.gray.opacity(0.1))

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(config.name)
                        .font(.title3).fontWeight(.semibold)
                    Spacer()
                    if let (label, color) = statusText {
                        Text(label)
                            .font(.caption)
                            .foregroundColor(color)
                    }
                    VPNStatusIndicator(
                        isConnected: connection.isConnected,
                        isConnecting: connection.isConnecting,
                        isReconnecting: connection.isReconnecting,
                        isWaitingForNetwork: connection.isWaitingForNetwork,
                        isRecoveringConnection: connection.isRecoveringConnection,
                        isDisconnecting: connection.isDisconnecting,
                        hasFailure: hasFailureState
                    )
                }

                if let active = connection.activeConfiguration, connection.hasPendingConfigurationChanges {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Current connection: \(active.serverAddress) (\(active.username), \(active.effectiveProtocol))")
                            .font(.subheadline)
                            .foregroundColor(.primary)
                        Text("Next connection: \(config.serverAddress) (\(config.username), \(config.effectiveProtocol)) — Applies on reconnect")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                } else {
                    Text(displayedConfig.serverAddress)
                        .font(.subheadline).foregroundColor(.secondary)
                }

                if case .accountLocked(let message) = connection.phase {
                    Text(message).font(.caption).foregroundColor(.red).textSelection(.enabled)
                } else if case .failed(let message) = connection.phase {
                    Text(message).font(.caption).foregroundColor(.red).textSelection(.enabled)
                }

                HStack(spacing: 12) {
                    Label(displayedConfig.username, systemImage: "person.fill")
                        .font(.caption).foregroundColor(.gray)
                    if let group = displayedConfig.trimmedAuthGroup {
                        Label(group, systemImage: "person.3.fill")
                            .font(.caption).foregroundColor(.gray)
                    }
                    Label(displayedConfig.effectiveProtocol, systemImage: "network")
                        .font(.caption).foregroundColor(.gray)
                    if config.autoReconnect {
                        Label("Auto Reconnect", systemImage: "arrow.triangle.2.circlepath")
                            .font(.caption).foregroundColor(.gray)
                    }
                }

                HStack(spacing: 10) {
                    Button(action: onConnect) {
                        Label("Connect", systemImage: "link")
                    }
                    .buttonStyle(.bordered)
                    .disabled(!connection.canConnect)

                    Button(action: onDisconnect) {
                        Label("Disconnect", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.bordered)
                    .disabled(
                        connection.isPendingDeletion ||
                        (connection.isDisconnecting && !connection.hasUnfinishedProcess) ||
                        (!connection.hasUnfinishedProcess && !connection.isReconnecting && !connection.isWaitingForNetwork)
                    )

                    if !connection.availableGroups.isEmpty && connection.canConnect {
                        Button(action: { connection.isSelectingGroup = true }) {
                            Label("Select Group", systemImage: "person.3")
                        }
                        .buttonStyle(.borderedProminent)
                    }

                    if connection.hasPendingConfigurationChanges, let onReconnectToApply {
                        Button(action: onReconnectToApply) {
                            Label("Reconnect to Apply", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(connection.isDisconnecting || connection.isPendingDeletion)
                    }

                    Button(action: onEdit) {
                        Image(systemName: "pencil")
                    }
                    .buttonStyle(.borderless)
                    .disabled(connection.isPendingDeletion)
                    .help("Edit")

                    Button(action: onShowLogs) {
                        Image(systemName: "info.circle")
                    }.buttonStyle(.borderless).help("Logs")

                    Button(action: onDelete) {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .disabled(connection.isPendingDeletion)
                    .help("Delete")
                }
            }
            .padding()
        }
        .padding(.vertical, 4)
        .sheet(isPresented: $connection.isSelectingGroup) {
            SelectVPNGroupView(
                config: config,
                groups: connection.availableGroups,
                initialGroup: config.trimmedAuthGroup
            ) { selectedGroup in
                try onSelectGroup?(selectedGroup)
            }
        }
    }
}
