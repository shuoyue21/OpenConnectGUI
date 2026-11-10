import SwiftUI

/// A view that displays the list of saved VPN configurations,
/// and allows adding or removing configurations.
struct VPNListView: View {
    @ObservedObject var store: VPNConfigurationStore
    private var connectionStore: ConnectionStore { store.connections }
    @State private var showingAddSheet = false
    @State private var selectedConfig: VPNConfiguration?
    @State private var showingLogsFor: VPNConfiguration?
    @State private var editingConfig: VPNConfiguration?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image("HeaderIcon")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 32, height: 32)
                    .clipShape(RoundedRectangle(cornerRadius: 6))

                Text("VPN Configurations")
                    .font(.title2)
                    .fontWeight(.semibold)

                Spacer()

                Button(action: { showingAddSheet = true }) {
                    Label("Add VPN", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal)
            .padding(.vertical, 10)

            Divider()

            List {
                ForEach(store.configurations) { config in
                    if let connection = connectionStore.connection(for: config) {
                        ConnectionRow(
                            config: config,
                            connection: connection,
                            onConnect: {
                                if !connection.needsCredentials,
                                   !connection.isAccountLocked,
                                   let savedPassword = store.savedPassword(for: config) {
                                    if connection.hasUnfinishedProcess {
                                        connection.reconnectToApplyChanges(with: savedPassword)
                                    } else {
                                        connection.connect(with: savedPassword)
                                    }
                                } else {
                                    selectedConfig = config
                                }
                            },
                            onDisconnect: { connection.disconnect() },
                            onReconnectToApply: {
                                if let savedPassword = store.savedPassword(for: config) {
                                    connection.reconnectToApplyChanges(with: savedPassword)
                                } else {
                                    connection.reconnectToApplyChanges(with: nil)
                                    selectedConfig = config
                                }
                            },
                            onSelectGroup: { selectedGroup in
                                var updated = config
                                updated.authGroup = selectedGroup
                                try store.update(updated, password: nil)
                                connection.connectWithSelectedGroup(
                                    selectedGroup,
                                    updatedConfig: updated,
                                    fallbackPassword: store.savedPassword(for: updated)
                                )
                            },
                            onEdit: { editingConfig = config },
                            onShowLogs: { showingLogsFor = config },
                            onDelete: {
                                do { try store.remove(config) } catch {
                                    store.errorMessage = error.localizedDescription
                                }
                            }
                        )
                    }
                }
                .onDelete { offsets in
                    let toDelete = offsets.map { store.configurations[$0] }
                    toDelete.forEach { cfg in
                        do { try store.remove(cfg) } catch {
                            store.errorMessage = error.localizedDescription
                        }
                    }
                }
            }
            .listStyle(.plain)
        }
        .sheet(isPresented: $showingAddSheet) {
            AddVPNView(store: store)
        }
        .sheet(item: $selectedConfig) { config in
            if let connection = connectionStore.connection(for: config) {
                if !connection.needsCredentials,
                   !connection.isAccountLocked,
                   let savedPassword = store.savedPassword(for: config) {
                    AutoConnectView(config: config, password: savedPassword) {
                        if connection.hasUnfinishedProcess {
                            connection.reconnectToApplyChanges(with: savedPassword)
                        } else {
                            connection.connect(with: savedPassword)
                        }
                        selectedConfig = nil
                    }
                } else {
                    ConnectVPNView(config: config) { vpnPassword, remember in
                        try store.prepareConnection(config, password: vpnPassword, remember: remember)
                        if connection.hasUnfinishedProcess {
                            connection.reconnectToApplyChanges(with: vpnPassword)
                        } else {
                            connection.connect(with: vpnPassword)
                        }
                    }
                }
            }
        }
        .sheet(item: $showingLogsFor) { config in
            if let connection = connectionStore.connection(for: config) {
                VPNLogsView(connection: connection)
            }
        }
        .sheet(item: $editingConfig) { config in
            EditVPNView(store: store, config: config)
        }
        .onChange(of: store.requestedConnectConfig) { _, requested in
            if let requested {
                store.requestedConnectConfig = nil
                if let connection = connectionStore.connection(for: requested),
                   !connection.needsCredentials,
                   !connection.isAccountLocked,
                   let savedPassword = store.savedPassword(for: requested) {
                    if connection.hasUnfinishedProcess {
                        connection.reconnectToApplyChanges(with: savedPassword)
                    } else {
                        connection.connect(with: savedPassword)
                    }
                } else {
                    selectedConfig = requested
                }
            }
        }
        .frame(minWidth: 600, minHeight: 400)
        .alert(
            "VPN configuration notice",
            isPresented: Binding(
                get: { store.errorMessage != nil },
                set: { if !$0 { store.errorMessage = nil } }
            )
        ) {
            Button("OK") { store.errorMessage = nil }
        } message: {
            Text(store.errorMessage ?? "")
        }
    }
}
