import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        if model.api == nil {
            NavigationStack { SettingsView() }
        } else {
            TabView(selection: $model.selectedTab) {
                ApprovalsView()
                    .tabItem { Label("Approvals", systemImage: "checkmark.shield") }
                    .badge(model.pending.count)
                    .tag(AppTab.approvals)
                ServersView()
                    .tabItem { Label("Servers", systemImage: "server.rack") }
                    .tag(AppTab.servers)
                UsersView()
                    .tabItem { Label("Clients", systemImage: "person.2") }
                    .tag(AppTab.users)
                ActivityView()
                    .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
                    .tag(AppTab.activity)
                NavigationStack { SettingsView() }
                    .tabItem { Label("Settings", systemImage: "gear") }
                    .tag(AppTab.settings)
            }
        }
    }
}

struct ActionBadge: View {
    var action: PolicyAction

    var body: some View {
        Label(action.label, systemImage: action.systemImage)
            .font(.caption.weight(.semibold))
            .foregroundStyle(action.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(action.color.opacity(0.12), in: Capsule())
    }
}

/// Menu to pick allow / ask / deny, with an optional "use default" entry.
struct ActionMenu: View {
    var current: PolicyAction
    var defaultLabel: String?
    var onSelect: (PolicyAction?) -> Void

    var body: some View {
        Menu {
            ForEach(PolicyAction.allCases) { action in
                Button { onSelect(action) } label: { Label(action.label, systemImage: action.systemImage) }
            }
            if let defaultLabel {
                Divider()
                Button(defaultLabel) { onSelect(nil) }
            }
        } label: {
            ActionBadge(action: current)
        }
    }
}

struct LiveIndicator: View {
    var isLive: Bool

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(isLive ? Color.green : Color.secondary).frame(width: 7, height: 7)
            Text(isLive ? "Live" : "Offline").font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct StatusDot: View {
    var state: String?

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 9, height: 9)
            .accessibilityLabel(state ?? "idle")
    }

    private var color: Color {
        switch state {
        case "connected": .green
        case "connecting": .yellow
        case "error": .red
        default: .secondary
        }
    }
}

struct CodeBlock: View {
    var text: String

    var body: some View {
        ScrollView(.horizontal) {
            Text(text)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct CopyButton: View {
    var text: String
    var label = "Copy"
    @State private var copied = false

    var body: some View {
        Button {
            UIPasteboard.general.string = text
            copied = true
            Task {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                copied = false
            }
        } label: {
            Label(copied ? "Copied" : label, systemImage: copied ? "checkmark" : "doc.on.doc")
        }
    }
}

/// Runs an async throwing action and shows its error in an alert.
@MainActor
@Observable
final class ErrorPresenter {
    var message: String?

    func run(_ action: @escaping () async throws -> Void) {
        Task {
            do { try await action() } catch { message = error.localizedDescription }
        }
    }
}

extension View {
    func errorAlert(_ presenter: ErrorPresenter) -> some View {
        alert("Something went wrong", isPresented: Binding(get: { presenter.message != nil }, set: { if !$0 { presenter.message = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(presenter.message ?? "")
        }
    }
}

extension Date {
    var relative: String { formatted(.relative(presentation: .named)) }
}

/// Parses "KEY=VALUE" (or "Header: value") lines into a dictionary, and back.
enum KeyValueText {
    static func parse(_ text: String, separator: Character) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.split(separator: "\n") {
            guard let i = line.firstIndex(of: separator) else { continue }
            let key = line[..<i].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: i)...].trimmingCharacters(in: .whitespaces)
            if !key.isEmpty { out[key] = value }
        }
        return out
    }

    static func format(_ dict: [String: String], separator: String) -> String {
        dict.keys.sorted().map { "\($0)\(separator)\(dict[$0]!)" }.joined(separator: "\n")
    }
}
