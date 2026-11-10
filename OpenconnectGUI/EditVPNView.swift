//
//  EditVPNView.swift
//  OpenconnectGUI
//
//  Created by Mikołaj Jucha on 23/04/2025.
//
import SwiftUI

/// A view for editing an existing VPN configuration.
struct EditVPNView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VPNConfigurationStore
    @State var config: VPNConfiguration
    @State private var vpnPassword: String = ""
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("Edit VPN Configuration")
                .font(.title2)
                .padding(.top)

            TextField("Connection Name", text: $config.name)
            TextField("Server Address", text: $config.serverAddress)
            TextField("Username", text: $config.username)
            TextField(
                "Group (optional)",
                text: Binding(
                    get: { config.authGroup ?? "" },
                    set: { config.authGroup = $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
                )
            )

            Picker("Protocol", selection: $config.protocolType) {
                ForEach(VPNProtocolOption.supportedProtocols) { option in
                    Text(option.label).tag(option.value as String?)
                }
            }

            SecureField("New VPN Password (leave blank to keep)", text: $vpnPassword)
                .disabled(!config.rememberCredentials)

            Toggle("Remember Credentials", isOn: $config.rememberCredentials)
                .onChange(of: config.rememberCredentials) { _, remember in if !remember { vpnPassword = "" } }
            Toggle("Auto Reconnect", isOn: $config.autoReconnect)

            HStack {
                Button("Cancel") {
                    dismiss()
                }

                Spacer()

                Button("Save Changes") {
                    do {
                        try store.update(config, password: vpnPassword.isEmpty ? nil : vpnPassword)
                        dismiss()
                    } catch { errorMessage = error.localizedDescription }
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top)
        }
        .padding()
        .frame(width: 400)
        .alert("Could not save VPN", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
    }
}
