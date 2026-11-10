import Foundation

enum VPNExecutionStage: String, Codable, Equatable, Sendable {
    case setup
    case authenticating
    case tunneling
}

enum VPNTransportEvent: Equatable {
    case connecting
    case tunnelStarting
    case output(Data)
    case ended(VPNExitOutcome)
    case failed(String)

    static func ended(_ status: Int32) -> VPNTransportEvent {
        .ended(VPNExitOutcome(status: status))
    }
}

@MainActor protocol VPNTransport: AnyObject {
    func start(session: UUID, config: VPNConfiguration, password: String,
               receive: @escaping @MainActor (VPNTransportEvent) -> Void)
    func stop(session: UUID)
}
