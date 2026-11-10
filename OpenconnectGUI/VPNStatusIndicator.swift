import SwiftUI

struct VPNStatusIndicator: View {
    let isConnected: Bool
    var isConnecting: Bool = false
    var isReconnecting: Bool = false
    var isWaitingForNetwork: Bool = false
    var isRecoveringConnection: Bool = false
    var isDisconnecting: Bool = false
    var hasFailure: Bool = false

    private var statusColor: Color {
        if isConnected {
            return .green
        } else if isWaitingForNetwork || isRecoveringConnection || isConnecting || isReconnecting || isDisconnecting {
            return .orange
        } else if hasFailure {
            return .red
        } else {
            return .gray
        }
    }

    private var statusHelpText: String {
        if isConnected {
            return "Connected"
        } else if isWaitingForNetwork {
            return "Waiting for network"
        } else if isRecoveringConnection {
            return "Recovering connection"
        } else if isReconnecting {
            return "Reconnecting"
        } else if isDisconnecting {
            return "Disconnecting"
        } else if isConnecting {
            return "Connecting"
        } else if hasFailure {
            return "Action required"
        } else {
            return "Disconnected"
        }
    }

    var body: some View {
        Circle()
            .fill(statusColor)
            .frame(width: 12, height: 12)
            .overlay(
                Circle()
                    .stroke(Color.secondary.opacity(0.5), lineWidth: 1)
            )
            .help(statusHelpText)
    }
}
