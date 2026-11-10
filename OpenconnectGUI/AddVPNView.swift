//
//  AddVPNView.swift
//  OpenconnectGUI
//
//  Created by Mikołaj Jucha on 23/04/2025.
//
import SwiftUI

/// Represents a user-friendly display name and its associated protocol value
struct VPNProtocolOption: Identifiable {
    let id = UUID()
    let label: String
    let value: String

    static let supportedProtocols: [VPNProtocolOption] = [
        VPNProtocolOption(label: "Cisco AnyConnect", value: "anyconnect"),
        VPNProtocolOption(label: "Juniper Network Connect", value: "nc"),
        VPNProtocolOption(label: "Pulse Secure", value: "pulse"),
        VPNProtocolOption(label: "GlobalProtect", value: "gp"),
        VPNProtocolOption(label: "F5 BIG-IP", value: "f5"),
        VPNProtocolOption(label: "Fortinet FortiGate", value: "fortinet"),
        VPNProtocolOption(label: "Array Networks", value: "array")
    ]
}

/// A sheet that allows users to enter and save a new VPN configuration.
struct AddVPNView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VPNConfigurationStore

    @State private var name = ""
    @State private var serverAddress = ""
    @State private var username = ""
    @State private var authGroup = ""
    @State private var protocolType: String = "anyconnect"
    @State private var rememberCredentials = true
    @State private var autoReconnect = true
    @State private var vpnPassword = ""
    @State private var errorMessage: String?
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Configure Connection")
                .font(.title2)
                .fontWeight(.bold)
                .padding(.bottom, 8)

            Form {
                TextField("Connection Name", text: $name)
                TextField("Server Address", text: $serverAddress)
                TextField("Username", text: $username)
                TextField("Group (optional)", text: $authGroup)
                
                Picker("Protocol", selection: $protocolType) {
                    ForEach(VPNProtocolOption.supportedProtocols) { option in
                        Text(option.label).tag(option.value)
                    }
                }
                .pickerStyle(.menu)
                SecureField("VPN Password (optional)", text: $vpnPassword)
                    .disabled(!rememberCredentials)
                Toggle("Remember Credentials", isOn: $rememberCredentials)
                    .onChange(of: rememberCredentials) { _, remember in if !remember { vpnPassword = "" } }
                if !rememberCredentials { Text("You will enter your password when connecting.").font(.caption) }
                Toggle("Auto Reconnect", isOn: $autoReconnect)
            }

            HStack {
                Spacer()
                Button("Cancel") {
                    dismiss()
                }
                Button("Save") {
                    let shouldRemember = rememberCredentials
                    let newConfig = VPNConfiguration(
                        name: name,
                        serverAddress: serverAddress,
                        username: username,
                        protocolType: protocolType,
                        authGroup: authGroup,
                        rememberCredentials: shouldRemember,
                        autoReconnect: autoReconnect
                    )
                    do {
                        try store.add(newConfig, password: vpnPassword)
                        dismiss()
                    } catch { errorMessage = error.localizedDescription }
                }
                .disabled(name.isEmpty || serverAddress.isEmpty || username.isEmpty)
            }
            .padding(.top)
        }
        .padding()
        .frame(width: 420)
        .alert("Could not save VPN", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
    }
}
