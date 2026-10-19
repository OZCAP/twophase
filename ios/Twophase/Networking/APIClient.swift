import Foundation

struct ServerConnection: Codable, Equatable {
    var baseURL: URL
    var adminToken: String

    /// URL MCP clients use for a given server slug.
    func clientURL(slug: String) -> URL {
        baseURL.appending(path: "mcp").appending(path: slug)
    }
}

struct APIError: LocalizedError {
    var status: Int
    var message: String
    var errorDescription: String? { message }
}

private struct ErrorBody: Decodable { var error: String }

/// Thin client for the proxy's `/admin/api`.
final class APIClient {
    let connection: ServerConnection
    private let session: URLSession

    init(connection: ServerConnection) {
        self.connection = connection
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = false
        session = URLSession(configuration: config)
    }

    // MARK: Core

    private func makeRequest(_ method: String, _ path: String, query: [String: String?] = [:], body: (any Encodable)? = nil) throws -> URLRequest {
        var components = URLComponents(url: connection.baseURL.appending(path: "admin/api").appending(path: path), resolvingAgainstBaseURL: false)!
        let items = query.compactMap { k, v in v.map { URLQueryItem(name: k, value: $0) } }
        if !items.isEmpty { components.queryItems = items }
        var req = URLRequest(url: components.url!)
        req.httpMethod = method
        req.setValue("Bearer \(connection.adminToken)", forHTTPHeaderField: "Authorization")
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(body)
        }
        return req
    }

    private func send(_ req: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let message = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error ?? HTTPURLResponse.localizedString(forStatusCode: status)
            throw APIError(status: status, message: message)
        }
        return data
    }

    func get<T: Decodable>(_ path: String, query: [String: String?] = [:]) async throws -> T {
        try JSONDecoder.api.decode(T.self, from: try await send(makeRequest("GET", path, query: query)))
    }

    func call<T: Decodable>(_ method: String, _ path: String, body: (any Encodable)? = nil) async throws -> T {
        try JSONDecoder.api.decode(T.self, from: try await send(makeRequest(method, path, body: body)))
    }

    func call(_ method: String, _ path: String, body: (any Encodable)? = nil) async throws {
        _ = try await send(makeRequest(method, path, body: body))
    }

    // MARK: Endpoints

    func status() async throws -> ProxyStatus { try await get("status") }

    func servers() async throws -> [MCPServer] { try await get("servers") }
    func server(_ id: String) async throws -> MCPServer { try await get("servers/\(id)") }
    func createServer(_ draft: ServerDraft) async throws -> MCPServer { try await call("POST", "servers", body: draft) }
    func updateServer(_ id: String, _ draft: ServerDraft) async throws -> MCPServer { try await call("PATCH", "servers/\(id)", body: draft) }
    func deleteServer(_ id: String) async throws { try await call("DELETE", "servers/\(id)") }
    func restartServer(_ id: String) async throws -> MCPServer { try await call("POST", "servers/\(id)/restart") }
    func tools(serverId: String, userId: String? = nil) async throws -> [ToolInfo] {
        try await get("servers/\(serverId)/tools", query: ["userId": userId])
    }

    func users() async throws -> [ProxyUser] { try await get("users") }
    func createUser(name: String, serverIds: [String]) async throws -> IssuedToken {
        struct Body: Encodable { var name: String; var serverIds: [String] }
        return try await call("POST", "users", body: Body(name: name, serverIds: serverIds))
    }
    func updateUser(_ id: String, name: String? = nil, enabled: Bool? = nil, serverIds: [String]? = nil) async throws -> ProxyUser {
        struct Body: Encodable { var name: String?; var enabled: Bool?; var serverIds: [String]? }
        return try await call("PATCH", "users/\(id)", body: Body(name: name, enabled: enabled, serverIds: serverIds))
    }
    func rotateToken(_ id: String) async throws -> IssuedToken { try await call("POST", "users/\(id)/rotate-token") }
    func deleteUser(_ id: String) async throws { try await call("DELETE", "users/\(id)") }

    func rules(serverId: String? = nil, userId: String? = nil) async throws -> [Rule] {
        try await get("rules", query: ["serverId": serverId, "userId": userId])
    }
    func createRule(_ draft: RuleDraft) async throws -> Rule { try await call("POST", "rules", body: draft) }
    func updateRule(_ id: String, _ draft: RuleDraft) async throws -> Rule { try await call("PATCH", "rules/\(id)", body: draft) }
    func deleteRule(_ id: String) async throws { try await call("DELETE", "rules/\(id)") }

    func grants() async throws -> [Grant] { try await get("grants") }
    func createGrant(_ draft: GrantDraft) async throws -> Grant { try await call("POST", "grants", body: draft) }
    func revokeGrant(_ id: String) async throws { try await call("DELETE", "grants/\(id)") }

    func approvals(status: ApprovalStatus? = nil, limit: Int = 50) async throws -> [Approval] {
        try await get("approvals", query: ["status": status?.rawValue, "limit": String(limit)])
    }
    func approval(_ id: String) async throws -> Approval { try await get("approvals/\(id)") }
    func decide(_ id: String, _ decision: Decision) async throws -> Approval {
        try await call("POST", "approvals/\(id)/decision", body: decision.body)
    }

    func audit(before: Int? = nil, limit: Int = 50) async throws -> [AuditEntry] {
        try await get("audit", query: ["before": before.map(String.init), "limit": String(limit)])
    }

    func registerDevice(token: String, environment: String) async throws {
        struct Body: Encodable { var token: String; var environment: String }
        try await call("POST", "devices", body: Body(token: token, environment: environment))
    }

    // MARK: Live events

    struct ServerEvent {
        var name: String
        var data: Data
    }

    /// Server-sent events from `/admin/api/events`. Ends (or throws) when the connection drops.
    func events() -> AsyncThrowingStream<ServerEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    var req = try makeRequest("GET", "events")
                    req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                    req.timeoutInterval = 60 // idle timeout; the server pings every 20s
                    let (bytes, response) = try await session.bytes(for: req)
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    guard status == 200 else { throw APIError(status: status, message: "Event stream failed (\(status))") }
                    // `lines` drops blank lines, so dispatch on each `data:` line (the server sends one per event).
                    var name = "message"
                    for try await line in bytes.lines {
                        if line.hasPrefix("event:") {
                            name = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
                        } else if line.hasPrefix("data:") {
                            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                            continuation.yield(ServerEvent(name: name, data: Data(payload.utf8)))
                            name = "message"
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

extension JSONDecoder {
    /// Server timestamps are ISO-8601 with milliseconds, which `.iso8601` alone rejects.
    static let api: JSONDecoder = {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            if let date = fractional.date(from: s) ?? plain.date(from: s) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Bad date \(s)"))
        }
        return d
    }()
}
