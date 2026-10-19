import SwiftUI
import UserNotifications

@main
struct TwophaseApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase
    @State private var model = AppModel.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .task { model.start() }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active { Task { await model.refreshApprovals() } }
                }
        }
    }
}

enum NotificationAction {
    static let category = "APPROVAL_REQUEST"
    static let approveOnce = "APPROVE_ONCE"
    static let approveTenMinutes = "APPROVE_10M"
    static let deny = "DENY"
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        // Approving from the lock screen requires unlocking the device first.
        center.setNotificationCategories([
            UNNotificationCategory(
                identifier: NotificationAction.category,
                actions: [
                    UNNotificationAction(identifier: NotificationAction.approveOnce, title: "Approve", options: [.authenticationRequired]),
                    UNNotificationAction(identifier: NotificationAction.approveTenMinutes, title: "Approve & trust tool for 10 min", options: [.authenticationRequired]),
                    UNNotificationAction(identifier: NotificationAction.deny, title: "Deny", options: [.destructive]),
                ],
                intentIdentifiers: []
            ),
        ])
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in AppModel.shared.didRegisterForPush(deviceToken: deviceToken) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("Push registration failed: \(error.localizedDescription)")
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound, .list]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let id = response.notification.request.content.userInfo["approvalId"] as? String else { return }
        let decision: Decision?
        switch response.actionIdentifier {
        case NotificationAction.approveOnce: decision = .once
        case NotificationAction.approveTenMinutes: decision = .trust(scope: .tool, minutes: 10)
        case NotificationAction.deny: decision = .deny
        default: decision = nil
        }
        await MainActor.run {
            let model = AppModel.shared
            if decision == nil {
                model.selectedTab = .approvals
                model.openApprovalId = id
            }
        }
        if let decision {
            try? await AppModel.shared.decide(id, decision)
        }
    }
}
