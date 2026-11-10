import SwiftUI

/// Displays real-time VPN connection logs with auto-scrolling, copy, and clear actions.
struct VPNLogsView: View {
    @ObservedObject var connection: VPNConnectionState
    @Environment(\.dismiss) var dismiss
    @State private var showCopiedMessage = false

    private var displayedLogs: [String] {
        Array(connection.logs.suffix(200))
    }

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Connection Logs")
                    .font(.headline)
                Spacer()
                Button("Close") {
                    dismiss()
                }
            }

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(displayedLogs.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(size: 12, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                    }
                    .padding(.bottom)
                }
                .onAppear {
                    if !displayedLogs.isEmpty {
                        proxy.scrollTo(displayedLogs.count - 1, anchor: .bottom)
                    }
                }
                .onChange(of: connection.logs.count) { _, _ in
                    if !displayedLogs.isEmpty {
                        proxy.scrollTo(displayedLogs.count - 1, anchor: .bottom)
                    }
                }
            }

            HStack {
                Button("Clear") {
                    connection.clearLogs()
                }
                .disabled(connection.logs.isEmpty)

                Spacer()

                Button("Copy to Clipboard") {
                    copyLogsToClipboard()
                }
                .disabled(connection.logs.isEmpty)

                if showCopiedMessage {
                    Text("✅ Copied")
                        .font(.caption)
                        .foregroundColor(.green)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.3), value: showCopiedMessage)
                }
            }
            .padding(.top, 8)
        }
        .padding()
        .frame(width: 500, height: 320)
    }

    private func copyLogsToClipboard() {
        let lastLogs = displayedLogs.joined(separator: "\n")
        
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lastLogs, forType: .string)
        #else
        UIPasteboard.general.string = lastLogs
        #endif

        showCopiedMessage = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            showCopiedMessage = false
        }
    }
}
