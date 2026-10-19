import Foundation
import SwiftUI

enum PolicyAction: String, Codable, CaseIterable, Identifiable {
    case allow, approve, deny

    var id: String { rawValue }

    var label: String {
        switch self {
        case .allow: "Allow"
        case .approve: "Ask"
        case .deny: "Deny"
        }
    }

    var systemImage: String {
        switch self {
        case .allow: "checkmark.circle.fill"
        case .approve: "hand.raised.fill"
        case .deny: "xmark.octagon.fill"
        }
    }

    var color: Color {
        switch self {
        case .allow: .green
        case .approve: .orange
        case .deny: .red
        }
    }
}

enum TransportKind: String, Codable, CaseIterable, Identifiable {
    case stdio, http
    var id: String { rawValue }
    var label: String { self == .stdio ? "Command (stdio)" : "Remote (HTTP)" }
}

struct UpstreamStatus: Codable, Hashable {
    var state: String
    var error: String?
}

struct MCPServer: Codable, Identifiable, Hashable {
    var id: String
    var slug: String
    var name: String
    var transport: TransportKind
    var command: String?
    var args: [String]
    var env: [String: String]
    var url: String?
    var headers: [String: String]
    var defaultAction: PolicyAction
    var enabled: Bool
    var createdAt: Date
    var status: UpstreamStatus?
    var stderr: [String]?
}

/// Body for creating/updating a server.
struct ServerDraft: Encodable {
    var slug = ""
    var name = ""
    var transport: TransportKind = .stdio
    var command: String?
    var args: [String] = []
    var env: [String: String] = [:]
    var url: String?
    var headers: [String: String] = [:]
    var defaultAction: PolicyAction = .approve
    var enabled = true

    init() {}

    init(_ s: MCPServer) {
        slug = s.slug
        name = s.name
        transport = s.transport
        command = s.command
        args = s.args
        env = s.env
        url = s.url
        headers = s.headers
        defaultAction = s.defaultAction
        enabled = s.enabled
    }
}

struct ProxyUser: Codable, Identifiable, Hashable {
    var id: String
    var name: String
    var tokenPrefix: String
    var enabled: Bool
    var serverIds: [String]
    var createdAt: Date
    var lastUsedAt: Date?
}

/// Returned when a user is created or their token rotated — the only time the token is visible.
struct IssuedToken: Codable, Identifiable {
    var user: ProxyUser
    var token: String
    var id: String { token }
}

struct Rule: Codable, Identifiable, Hashable {
    var id: String
    var serverId: String
    var userId: String?
    var toolPattern: String
    var action: PolicyAction
    var note: String?
    var createdAt: Date
    var serverName: String?
    var userName: String?
}

struct RuleDraft: Encodable {
    var serverId: String
    var userId: String?
    var toolPattern: String
    var action: PolicyAction
    var note: String?

    // Always send userId/note so an update can clear them (omitted = unchanged on the server).
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverId, forKey: .serverId)
        try c.encode(userId, forKey: .userId)
        try c.encode(toolPattern, forKey: .toolPattern)
        try c.encode(action, forKey: .action)
        try c.encode(note, forKey: .note)
    }

    enum CodingKeys: String, CodingKey { case serverId, userId, toolPattern, action, note }
}

struct Grant: Codable, Identifiable, Hashable {
    var id: String
    var serverId: String
    var userId: String?
    var toolName: String?
    var expiresAt: Date?
    var approvalId: String?
    var note: String?
    var createdAt: Date
    var serverName: String?
    var userName: String?

    var scopeDescription: String {
        let who = userName ?? "Everyone"
        let what = toolName ?? "all tools"
        return "\(who) · \(what) on \(serverName ?? "server")"
    }
}

struct GrantDraft: Encodable {
    var serverId: String
    var userId: String?
    var toolName: String?
    var durationMinutes: Int?
    var note: String?
}

enum ApprovalStatus: String, Codable {
    case pending, approved, denied, expired, cancelled
}

struct Approval: Codable, Identifiable, Hashable {
    var id: String
    var serverId: String
    var userId: String
    var toolName: String
    var arguments: JSONValue
    var status: ApprovalStatus
    var createdAt: Date
    var expiresAt: Date
    var decidedAt: Date?
    var grantId: String?
    var serverName: String?
    var userName: String?
}

/// What the operator decided for an approval.
enum Decision: Hashable {
    case deny
    case once
    /// Approve and open a trust window. `minutes == nil` means until revoked.
    case trust(scope: TrustScope, minutes: Int?)

    enum TrustScope: String { case tool, server }

    var body: DecisionBody {
        switch self {
        case .deny: DecisionBody(decision: "deny", scope: "once", durationMinutes: nil)
        case .once: DecisionBody(decision: "approve", scope: "once", durationMinutes: nil)
        case .trust(let scope, let minutes): DecisionBody(decision: "approve", scope: scope.rawValue, durationMinutes: minutes)
        }
    }
}

struct DecisionBody: Encodable {
    var decision: String
    var scope: String
    var durationMinutes: Int?
}

struct AuditEntry: Codable, Identifiable, Hashable {
    var id: Int
    var ts: Date
    var serverId: String
    var userId: String
    var toolName: String
    var arguments: JSONValue
    var decision: String
    var approvalId: String?
    var isError: Bool
    var error: String?
    var durationMs: Int?
    var serverName: String?
    var userName: String?

    var wasBlocked: Bool { ["denied", "rejected", "expired", "cancelled"].contains(decision) }
}

struct ToolInfo: Codable, Identifiable, Hashable {
    var name: String
    var title: String?
    var description: String?
    var readOnlyHint: Bool?
    var destructiveHint: Bool?
    var inputSchema: JSONValue?
    var action: PolicyAction
    var ruleId: String?
    var id: String { name }
}

struct ProxyStatus: Codable {
    var version: String
    var apnsEnabled: Bool
    var approvalTimeoutSeconds: Int
    var pendingApprovals: Int
}

/// Durations offered for trust windows. nil = until revoked.
let trustDurations: [(label: String, minutes: Int?)] = [
    ("10 minutes", 10),
    ("1 hour", 60),
    ("8 hours", 480),
    ("Until revoked", nil),
]
