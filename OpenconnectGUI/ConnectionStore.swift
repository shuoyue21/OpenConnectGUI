import Foundation
import Combine

@MainActor
final class ConnectionStore: ObservableObject {
    private var states: [UUID: VPNConnectionState] = [:]
    private var stateCancellables: [UUID: AnyCancellable] = [:]
    private var retiring: [VPNConnectionState] = []
    private let makeState: @MainActor (VPNConfiguration) -> VPNConnectionState

    init(makeState: @escaping @MainActor (VPNConfiguration) -> VPNConnectionState = { VPNConnectionState(config: $0) }) {
        self.makeState = makeState
    }

    /// Called by configuration mutations, never by View.body.
    func register(_ config: VPNConfiguration) {
        if let existing = states[config.id] {
            existing.updateConfig(config)
        } else {
            let state = makeState(config)
            states[config.id] = state
            stateCancellables[config.id] = state.objectWillChange.sink { [weak self] _ in
                self?.objectWillChange.send()
            }
        }
        retiring.removeAll { !$0.hasUnfinishedProcess }
        objectWillChange.send()
    }

    /// Pure lookup: repeated view evaluation always observes the same object.
    func connection(for config: VPNConfiguration) -> VPNConnectionState? {
        states[config.id]
    }

    func connection(id: UUID) -> VPNConnectionState? {
        states[id]
    }

    func credentialsChanged(for config: VPNConfiguration, password: String?) {
        states[config.id]?.credentialsChanged(password)
    }

    func remove(_ config: VPNConfiguration) {
        stateCancellables.removeValue(forKey: config.id)
        guard let state = states.removeValue(forKey: config.id) else { return }
        state.disconnect()
        if state.hasUnfinishedProcess {
            retiring.append(state)
        }
        objectWillChange.send()
    }

    func disconnectAll() {
        (Array(states.values) + retiring).forEach { $0.disconnect() }
    }

    func handleSystemWillSleep() {
        states.values.forEach { $0.systemWillSleep() }
    }

    func handleSystemDidWake() {
        states.values.forEach { $0.systemDidWake() }
    }

    var hasActiveSessions: Bool {
        (Array(states.values) + retiring).contains { $0.hasUnfinishedProcess }
    }

    var activeSessionDescriptions: [String] {
        (Array(states.values) + retiring)
            .filter { $0.hasUnfinishedProcess }
            .map { $0.activeConfiguration?.name ?? $0.config.name }
    }
}
