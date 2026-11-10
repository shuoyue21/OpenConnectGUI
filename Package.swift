// swift-tools-version: 6.0
import PackageDescription

// Runs lifecycle and privilege-boundary tests without launching the GUI or touching user credentials.
let package = Package(
    name: "OpenConnectCore",
    platforms: [.macOS(.v15)],
    products: [.library(name: "OpenConnectCore", targets: ["OpenConnectCore"])],
    targets: [
        .target(name: "OpenConnectCore", path: ".", exclude: [
            "OpenconnectGUI.xcodeproj", "OpenconnectGUITests", "OpenconnectGUIUITests", "Release", "PrivilegedHelper", "Support", "Scripts", "docs", "README.md", "LICENSE",
            "OpenconnectGUI/AddVPNView.swift", "OpenconnectGUI/AutoConnectView.swift", "OpenconnectGUI/ConnectVPNView.swift",
            "OpenconnectGUI/ConnectionRow.swift", "OpenconnectGUI/ContentView.swift", "OpenconnectGUI/EditVPNView.swift",
            "OpenconnectGUI/OpenconnectGUIApp.swift", "OpenconnectGUI/VPNListView.swift", "OpenconnectGUI/VPNLogsView.swift",
            "OpenconnectGUI/VPNStatusIndicator.swift", "OpenconnectGUI/Assets.xcassets", "OpenconnectGUI/Info.plist", "OpenconnectGUI/OpenconnectGUI.entitlements"
        ], sources: ["Shared", "OpenconnectGUI/VPNConfiguration.swift", "OpenconnectGUI/VPNConnectionState.swift",
                     "OpenconnectGUI/VPNTransport.swift", "OpenconnectGUI/HelperVPNTransport.swift", "OpenconnectGUI/AuthenticationResult.swift",
                     "OpenconnectGUI/ConnectionStore.swift", "OpenconnectGUI/VPNConfigurationStore.swift", "OpenconnectGUI/KeychainService.swift",
                     "OpenconnectGUI/NotificationManager.swift"]),
        .testTarget(name: "OpenConnectCoreTests", dependencies: ["OpenConnectCore"], path: "OpenconnectGUITests")
    ],
    swiftLanguageModes: [.v5]
)
