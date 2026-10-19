import Foundation
import Observation
import UIKit
import UserNotifications

enum AppTab: Hashable { case approvals, servers, users, activity, settings }

/// App-wide state: the proxy connection, live approval queue and the shared lists.
@MainActor
@Observable
final class AppModel {
    static let shared = AppModel()

    private(set) var api: APIClient?
    var selectedTab: AppTab = .approvals
    /// Set when a notification is tapped; the approvals tab navigates to it.
    var openApprovalId: String?

    private(set) var status: ProxyStatus?
    private(set) var pending: [Approval] = []
    private(set) var recent: [Approval] = []
    private(set) var grants: [Grant] = []
    private(set) var servers: [MCPServer] = []
    private(set) var users: [ProxyUser] = []
    private(set) var activity: [AuditEntry] = []
    private(set) var isLive = false

    private var eventTask: Task<Void, Never>?

    private init() {
        if let saved = Keychain.loadConnection() {
            api = APIClient(connection: saved)
        }
    }

    var connection: ServerConnection? { api?.connection }

    // MARK: Connection

    /// Validates credentials against the server, then persists them.
    func connect(_ connection: ServerConnection) async throws {
        let client = APIClient(connection: connection)
        status = try await client.status()
        Keychain.saveConnection(connection)
        api = client
        start()
    }

    func disconnect() {
        eventTask?.cancel()
        Keychain.saveConnection(nil)
        api = nil
        isLive = false
        pending = []; recent = []; grants = []; servers = []; users = []; activity = []
    }

    func start() {
        guard api != nil else { return }
        Task { await refreshAll() }
        startEvents()
        Task { await requestPushPermission() }
    }

    func refreshAll() async {
        async let a: Void = refreshApprovals()
        async let s: Void = refreshServers()
        async let u: Void = refreshUsers()
        async let act: Void = refreshActivity()
        _ = await (a, s, u, act)
        status = try? await api?.status()
    }

    // MARK: Approvals

    func refreshApprovals() async {
        guard let api else { return }
        async let p = api.approvals(status: .pending)
        async let r = api.approvals(limit: 40)
        async let g = api.grants()
        if let p = try? await p { pending = p.sorted { $0.createdAt < $1.createdAt } }
        if let r = try? await r { recent = r.filter { $0.status != .pending } }
        if let g = try? await g { grants = g }
        updateBadge()
    }

    func decide(_ approvalId: String, _ decision: Decision) async throws {
        guard let api else { return }
        let updated = try await api.decide(approvalId, decision)
        applyResolved(updated)
        if case .trust = decision { grants = (try? await api.grants()) ?? grants }
    }

    func trust(serverId: String, userId: String?, toolName: String? = nil, minutes: Int?) async throws {
        guard let api else { return }
        let grant = try await api.createGrant(GrantDraft(serverId: serverId, userId: userId, toolName: toolName, durationMinutes: minutes))
        grants.removeAll { $0.id == grant.id }
        grants.insert(grant, at: 0)
    }

    func revoke(_ grant: Grant) async throws {
        try await api?.revokeGrant(grant.id)
        grants.removeAll { $0.id == grant.id }
    }

    /// The approval with this id from local state, if known.
    func approval(_ id: String) -> Approval? {
        pending.first { $0.id == id } ?? recent.first { $0.id == id }
    }

    private func applyResolved(_ a: Approval) {
        pending.removeAll { $0.id == a.id }
        recent.removeAll { $0.id == a.id }
        recent.insert(a, at: 0)
        updateBadge()
        clearDeliveredNotification(approvalId: a.id)
    }

    // MARK: Servers & users

    func refreshServers() async {
        if let s = try? await api?.servers() { servers = s }
    }

    func refreshUsers() async {
        if let u = try? await api?.users() { users = u }
    }

    func server(_ id: String) -> MCPServer? { servers.first { $0.id == id } }
    func user(_ id: String) -> ProxyUser? { users.first { $0.id == id } }

    func replace(_ server: MCPServer) {
        if let i = servers.firstIndex(where: { $0.id == server.id }) { servers[i] = server } else { servers.append(server) }
        servers.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    func replace(_ user: ProxyUser) {
        if let i = users.firstIndex(where: { $0.id == user.id }) { users[i] = user } else { users.append(user) }
        users.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    func removeServer(_ id: String) { servers.removeAll { $0.id == id } }
    func removeUser(_ id: String) { users.removeAll { $0.id == id } }

    // MARK: Activity

    func refreshActivity() async {
        if let a = try? await api?.audit() { activity = a }
    }

    func loadMoreActivity() async {
        guard let last = activity.last, let more = try? await api?.audit(before: last.id), !more.isEmpty else { return }
        activity.append(contentsOf: more)
    }

    // MARK: Live events

    private func startEvents() {
        eventTask?.cancel()
        eventTask = Task { [weak self] in
            var backoff: UInt64 = 1
            while !Task.isCancelled {
                guard let api = self?.api else { return }
                do {
                    for try await event in api.events() {
                        if event.name == "ready" {
                            self?.isLive = true
                            backoff = 1
                            await self?.refreshApprovals() // catch up on anything missed while disconnected
                        }
                        self?.handle(event)
                    }
                } catch {}
                self?.isLive = false
                try? await Task.sleep(nanoseconds: backoff * 1_000_000_000)
                backoff = min(backoff * 2, 30)
            }
        }
    }

    private func handle(_ event: APIClient.ServerEvent) {
        let decoder = JSONDecoder.api
        switch event.name {
        case "approval.created":
            guard let a = try? decoder.decode(Approval.self, from: event.data), !pending.contains(where: { $0.id == a.id }) else { return }
            pending.append(a)
            updateBadge()
        case "approval.resolved":
            if let a = try? decoder.decode(Approval.self, from: event.data) { applyResolved(a) }
        case "grant.created":
            if let g = try? decoder.decode(Grant.self, from: event.data), !grants.contains(where: { $0.id == g.id }) {
                grants.insert(g, at: 0)
            }
        case "grant.revoked":
            struct Revoked: Decodable { var id: String }
            if let r = try? decoder.decode(Revoked.self, from: event.data) { grants.removeAll { $0.id == r.id } }
        case "audit":
            if let e = try? decoder.decode(AuditEntry.self, from: event.data), !activity.contains(where: { $0.id == e.id }) {
                activity.insert(e, at: 0)
            }
        default:
            break
        }
    }

    // MARK: Push

    func requestPushPermission() async {
        let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted { UIApplication.shared.registerForRemoteNotifications() }
    }

    func didRegisterForPush(deviceToken data: Data) {
        let token = data.map { String(format: "%02x", $0) }.joined()
        #if DEBUG
        let environment = "sandbox"
        #else
        let environment = "production"
        #endif
        Task { try? await api?.registerDevice(token: token, environment: environment) }
    }

    private func updateBadge() {
        UNUserNotificationCenter.current().setBadgeCount(pending.count)
    }

    private func clearDeliveredNotification(approvalId: String) {
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { notes in
            let ids = notes
                .filter { $0.request.content.userInfo["approvalId"] as? String == approvalId }
                .map(\.request.identifier)
            center.removeDeliveredNotifications(withIdentifiers: ids)
        }
    }
}
