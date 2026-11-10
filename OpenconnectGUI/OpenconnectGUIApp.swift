//
//  OpenconnectGUIApp.swift
//  OpenconnectGUI
//
//  Created by Mikołaj Jucha on 23/04/2025.
//

import SwiftUI
import AppKit
import UserNotifications
import ServiceManagement

@main
struct OpenconnectGUIApp: App {
    @StateObject private var store: VPNConfigurationStore
    @NSApplicationDelegateAdaptor(VPNAppDelegate.self) private var appDelegate

    init() {
        let testing = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil || NSClassFromString("XCTestCase") != nil
        let testFile = testing ? FileManager.default.temporaryDirectory.appendingPathComponent("OpenConnectGUI-tests-\(UUID().uuidString)/profiles.json") : nil
        _store = StateObject(wrappedValue: VPNConfigurationStore(configFileURL: testFile))
        guard !testing else { return }
        ManagedProcess.cleanupStaleTemporaryDirectories()
        let center = UNUserNotificationCenter.current()
        center.delegate = NotificationManager.shared
        center.requestAuthorization(options: [.alert, .sound]) { _, error in
            if let err = error {
                print("Notification auth error:", err)
            }
        }
    }

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView(store: store)
                .background(
                    MainWindowAccessor { window in
                        appDelegate.registerMainWindow(window)
                    }
                )
                .onAppear {
                    appDelegate.store = store
                    appDelegate.connections = store.connections
                }
        }
        .commands {
            CommandGroup(after: .appSettings) {
                Button("VPN Background Service Settings…") { SMAppService.openSystemSettingsLoginItems() }
            }
            CommandGroup(replacing: .saveItem) {
                Button("Close Window") {
                    appDelegate.hideMainWindow()
                }
                .keyboardShortcut("w", modifiers: .command)
            }
        }

        MenuBarExtra {
            VPNMenuBarView(store: store, appDelegate: appDelegate)
        } label: {
            VPNMenuBarLabel(store: store, connections: store.connections)
        }
    }
}

private struct MainWindowAccessor: NSViewRepresentable {
    let onResolve: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            if let window = view.window {
                onResolve(window)
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            if let window = nsView.window {
                onResolve(window)
            }
        }
    }
}

private struct VPNMenuBarLabel: View {
    @ObservedObject var store: VPNConfigurationStore
    @ObservedObject var connections: ConnectionStore

    var body: some View {
        Image(systemName: iconName)
            .help("OpenconnectGUI")
    }

    private var iconName: String {
        let states = store.configurations.compactMap { connections.connection(for: $0) }
        if states.contains(where: { $0.isConnected }) {
            return "lock.shield.fill"
        }
        if states.contains(where: {
            $0.isConnecting || $0.isReconnecting || $0.isWaitingForNetwork || $0.isRecoveringConnection || $0.isDisconnecting
        }) {
            return "arrow.triangle.2.circlepath"
        }
        return "shield.lefthalf.filled"
    }
}

private struct VPNMenuBarView: View {
    @ObservedObject var store: VPNConfigurationStore
    let appDelegate: VPNAppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            if store.configurations.isEmpty {
                Text("No VPN Configurations")
                    .foregroundColor(.secondary)
            } else {
                ForEach(store.configurations) { config in
                    if let connection = store.connections.connection(for: config) {
                        VPNMenuBarConfigurationItem(
                            config: config,
                            connection: connection,
                            store: store,
                            onRequireMainWindow: {
                                openMainWindow()
                            }
                        )
                    }
                }
            }
        }
        .onAppear {
            appDelegate.store = store
            appDelegate.connections = store.connections
        }

        Divider()

        Button("Show Main Window") {
            openMainWindow()
        }
        .keyboardShortcut("o", modifiers: [.command])

        Divider()

        Button("Quit OpenconnectGUI") {
            appDelegate.store = store
            appDelegate.connections = store.connections
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q", modifiers: [.command])
    }

    private func openMainWindow() {
        appDelegate.showMainWindow {
            openWindow(id: "main")
        }
    }
}

private struct VPNMenuBarConfigurationItem: View {
    let config: VPNConfiguration
    @ObservedObject var connection: VPNConnectionState
    @ObservedObject var store: VPNConfigurationStore
    let onRequireMainWindow: () -> Void

    var body: some View {
        Menu {
            Text("Server: \(config.serverAddress)")
            Text("Status: \(statusDescription)")
            Divider()
            if connection.isConnected || connection.isConnecting || connection.isReconnecting || connection.isWaitingForNetwork || connection.isRecoveringConnection || connection.hasUnfinishedProcess {
                Button("Disconnect") {
                    connection.disconnect()
                }
                .disabled(connection.isDisconnecting && !connection.hasUnfinishedProcess)
            } else {
                Button("Connect") {
                    connectFromMenuBar()
                }
                .disabled(connection.isDisconnecting)
            }
        } label: {
            Text("\(statusEmoji) \(config.name) — \(shortStatus)")
        }
        .onChange(of: connection.isSelectingGroup) { _, selecting in
            if selecting {
                onRequireMainWindow()
            }
        }
        .onChange(of: connection.needsCredentials) { _, needs in
            if needs {
                onRequireMainWindow()
            }
        }
    }

    private var statusEmoji: String {
        if connection.isConnected { return "🟢" }
        if connection.isConnecting || connection.isReconnecting || connection.isWaitingForNetwork || connection.isRecoveringConnection || connection.isDisconnecting {
            return "🟡"
        }
        return "⚪️"
    }

    private var shortStatus: String {
        if connection.isDisconnecting { return "Disconnecting…" }
        if connection.isWaitingForNetwork { return "Waiting for network…" }
        if connection.isRecoveringConnection { return "Recovering connection…" }
        if connection.isReconnecting { return "Reconnecting…" }
        if connection.isConnecting { return "Connecting…" }
        if connection.isConnected { return "Connected" }
        return "Disconnected"
    }

    private var statusDescription: String {
        switch connection.phase {
        case .accountLocked(let message), .failed(let message):
            return "\(shortStatus) (\(message))"
        default:
            return shortStatus
        }
    }

    private func connectFromMenuBar() {
        if !connection.needsCredentials,
           !connection.isAccountLocked,
           let savedPassword = store.savedPassword(for: config) {
            if connection.hasUnfinishedProcess {
                connection.reconnectToApplyChanges(with: savedPassword)
            } else {
                connection.connect(with: savedPassword)
            }
        } else {
            onRequireMainWindow()
            store.requestedConnectConfig = config
        }
    }
}

@MainActor
final class VPNAppDelegate: NSObject, NSApplicationDelegate {
    weak var store: VPNConfigurationStore?
    var connections: ConnectionStore?
    var terminationTimeout: TimeInterval = 12.0
    private var terminating = false
    weak var mainWindow: NSWindow?
    private var windowCloseObserver: NSObjectProtocol?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showMainWindow()
        return true
    }

    func registerMainWindow(_ window: NSWindow) {
        guard mainWindow !== window else { return }
        mainWindow = window
        window.isReleasedWhenClosed = false
        if let closeButton = window.standardWindowButton(.closeButton) {
            closeButton.target = self
            closeButton.action = #selector(handleCloseButton(_:))
        }
        if let windowCloseObserver {
            NotificationCenter.default.removeObserver(windowCloseObserver)
        }
        windowCloseObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, !self.terminating else { return }
                NSApp.setActivationPolicy(.accessory)
            }
        }
    }

    @objc private func handleCloseButton(_ sender: Any?) {
        hideMainWindow()
    }

    func hideMainWindow() {
        mainWindow?.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
    }

    func showMainWindow(fallbackOpen: (() -> Void)? = nil) {
        NSApp.setActivationPolicy(.regular)
        if let window = mainWindow {
            window.makeKeyAndOrderFront(nil)
        } else {
            fallbackOpen?()
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let connections else { return .terminateNow }
        connections.disconnectAll()
        guard connections.hasActiveSessions else { return .terminateNow }
        if !terminating {
            terminating = true
            let deadline = Date().addingTimeInterval(terminationTimeout)
            Task {
                while connections.hasActiveSessions && Date() < deadline {
                    try? await Task.sleep(for: .milliseconds(50))
                }
                let stillActive = connections.hasActiveSessions
                terminating = false
                if stillActive {
                    let pending = connections.activeSessionDescriptions.joined(separator: ", ")
                    store?.errorMessage = "Cannot quit yet because VPN disconnect or network cleanup has not completed for: \(pending). Connection controls remain available."
                    showMainWindow()
                    sender.reply(toApplicationShouldTerminate: false)
                } else {
                    sender.reply(toApplicationShouldTerminate: true)
                }
            }
        }
        return .terminateLater
    }
}
