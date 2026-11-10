//
//  NotificationManager.swift
//  OpenconnectGUI
//
//  Created by Mikołaj Jucha on 23/04/2025.
//
import Foundation
import UserNotifications

final class NotificationManager: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationManager()

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    static func postConnectionSuccess(for name: String) {
        let content = UNMutableNotificationContent()
        content.title = "VPN Connected"
        content.body  = "You are now connected to \(name)."
        content.sound = .default

        let req = UNNotificationRequest(
            identifier: "vpn.status.\(name)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(req) { err in
            if let e = err { print("Notification error:", e) }
        }
    }

    static func postConnectionDisconnected(for name: String) {
        let content = UNMutableNotificationContent()
        content.title = "VPN Disconnected"
        content.body  = "You are now disconnected from \(name)."
        content.sound = .default

        let req = UNNotificationRequest(
            identifier: "vpn.status.\(name)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(req) { err in
            if let e = err { print("Notification error:", e) }
        }
    }
}
