import SwiftUI

struct ConnectVPNView: View {
    let config: VPNConfiguration
    let onConnect: (_ vpnPassword: String, _ rememberVpn: Bool) throws -> Void

    @State private var vpnPassword: String = ""
    @State private var errorMessage: String?
    @State private var rememberVPN: Bool
    @Environment(\.dismiss) var dismiss

    init(config: VPNConfiguration, onConnect: @escaping (_ vpnPassword: String, _ rememberVpn: Bool) throws -> Void) {
        self.config = config
        self.onConnect = onConnect
        _rememberVPN = State(initialValue: config.rememberCredentials)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Connect to \(config.name)")
                .font(.title2)
                .bold()

            SecureField("VPN Password", text: $vpnPassword)
                .textFieldStyle(.roundedBorder)

            Toggle("Remember VPN Password", isOn: $rememberVPN)

            HStack {
                Spacer()
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Button("Connect") {
                    do {
                        try onConnect(vpnPassword, rememberVPN)
                        dismiss()
                    } catch { errorMessage = error.localizedDescription }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(vpnPassword.isEmpty)
            }
        }
        .padding()
        .frame(width: 400)
        .alert("Could not connect", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
    }
}

struct SelectVPNGroupView: View {
    let config: VPNConfiguration
    let groups: [String]
    let onSelect: (String) throws -> Void

    @State private var selectedGroup: String
    @State private var errorMessage: String?
    @Environment(\.dismiss) private var dismiss

    init(
        config: VPNConfiguration,
        groups: [String],
        initialGroup: String? = nil,
        onSelect: @escaping (String) throws -> Void
    ) {
        self.config = config
        self.groups = groups
        self.onSelect = onSelect
        let defaultChoice: String
        if let initialGroup, groups.contains(initialGroup) {
            defaultChoice = initialGroup
        } else {
            defaultChoice = groups.first ?? ""
        }
        _selectedGroup = State(initialValue: defaultChoice)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Select VPN Group")
                .font(.title2)
                .bold()

            Text("The server \(config.serverAddress) requires selecting a group before connecting:")
                .font(.subheadline)
                .foregroundColor(.secondary)

            Picker("Group", selection: $selectedGroup) {
                ForEach(groups, id: \.self) { group in
                    Text(group).tag(group)
                }
            }
            .pickerStyle(.menu)

            HStack {
                Spacer()
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Button("Connect") {
                    do {
                        try onSelect(selectedGroup)
                        dismiss()
                    } catch {
                        errorMessage = error.localizedDescription
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(selectedGroup.isEmpty)
            }
        }
        .padding()
        .frame(width: 420)
        .alert("Could not save group", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
    }
}
