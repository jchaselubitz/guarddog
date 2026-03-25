import AppKit
import Foundation
import GuardDogCore
import SwiftUI

@MainActor
@Observable
final class GuardDogAppModel {
    var protectedTools: [ProtectedTool] = []
    var allowedCallers: [AllowedCaller] = []
    var events: [ExecEvent] = []
    var selectedToolID: UUID?
    var protectionEnabled = true
    var isLoading = false
    var isMutating = false
    var errorMessage: String?

    func refresh() async {
        await runLoad {
            let client = try PolicyClientFactory.make()
            let snapshot = try client.snapshot()

            protectedTools = snapshot.protectedTools.sorted {
                $0.path.localizedStandardCompare($1.path) == .orderedAscending
            }
            allowedCallers = snapshot.allowedCallers.sorted { lhs, rhs in
                descriptor(for: lhs).localizedStandardCompare(descriptor(for: rhs)) == .orderedAscending
            }
            events = snapshot.events.sorted { $0.timestamp > $1.timestamp }
            protectionEnabled = snapshot.settings.isEnabled

            if let selectedToolID, protectedTools.contains(where: { $0.id == selectedToolID }) {
                self.selectedToolID = selectedToolID
            } else {
                selectedToolID = protectedTools.first?.id
            }
        }
    }

    func setProtectionEnabled(_ enabled: Bool) async {
        await runMutation {
            let client = try PolicyClientFactory.make()
            try client.setEnabled(enabled)
            protectionEnabled = enabled
            try loadState(using: client)
        }
    }

    func addProtectedTool() async {
        guard let url = openFilePanel(
            title: "Choose a Protected Tool",
            prompt: "Protect Tool",
            message: "Select a CLI executable to protect."
        ) else {
            return
        }

        await runMutation {
            let client = try PolicyClientFactory.make()
            let tool = try client.addProtectedTool(path: url.path, hash: nil, signingIdentity: nil)
            try loadState(using: client)
            selectedToolID = tool.id
        }
    }

    func removeProtectedTool(id: UUID) async {
        await runMutation {
            let client = try PolicyClientFactory.make()
            _ = try client.removeProtectedTool(reference: id.uuidString)
            try loadState(using: client)
        }
    }

    func addAllowedCaller(for toolID: UUID) async {
        guard let url = openFilePanel(
            title: "Choose an Allowed App",
            prompt: "Allow App",
            message: "Select the app or executable that may launch this protected tool."
        ) else {
            return
        }

        let bundleID = Bundle(url: url)?.bundleIdentifier
        let path = url.path

        await runMutation {
            let client = try PolicyClientFactory.make()
            _ = try client.addAllowedCaller(
                toolReference: toolID.uuidString,
                bundleID: bundleID,
                teamID: nil,
                path: path
            )
            try loadState(using: client)
        }
    }

    func removeAllowedCaller(id: UUID) async {
        await runMutation {
            let client = try PolicyClientFactory.make()
            _ = try client.removeAllowedCaller(id: id)
            try loadState(using: client)
        }
    }

    func clearError() {
        errorMessage = nil
    }

    var selectedTool: ProtectedTool? {
        guard let selectedToolID else { return protectedTools.first }
        return protectedTools.first(where: { $0.id == selectedToolID })
    }

    var selectedToolAllowedCallers: [AllowedCaller] {
        guard let toolID = selectedTool?.id else { return [] }
        return allowedCallers.filter { $0.toolID == toolID }
    }

    func toolDisplayName(_ tool: ProtectedTool) -> String {
        URL(fileURLWithPath: tool.path).lastPathComponent
    }

    func callerDisplayName(_ caller: AllowedCaller) -> String {
        if let bundleID = caller.bundleID, !bundleID.isEmpty {
            return bundleID
        }
        if let path = caller.path, !path.isEmpty {
            return URL(fileURLWithPath: path).lastPathComponent
        }
        return caller.id.uuidString
    }

    func callerDetail(_ caller: AllowedCaller) -> String {
        descriptor(for: caller)
    }

    func eventTitle(_ event: ExecEvent) -> String {
        URL(fileURLWithPath: event.toolPath).lastPathComponent
    }

    func eventSubtitle(_ event: ExecEvent) -> String {
        let origin = [event.callerBundleID, event.callerExecutablePath].compactMap { $0 }.joined(separator: " • ")
        if origin.isEmpty {
            return event.reason
        }
        return "\(origin) • \(event.reason)"
    }

    private func loadState(using client: PolicyClient) throws {
        let snapshot = try client.snapshot()
        protectedTools = snapshot.protectedTools.sorted {
            $0.path.localizedStandardCompare($1.path) == .orderedAscending
        }
        allowedCallers = snapshot.allowedCallers.sorted { lhs, rhs in
            descriptor(for: lhs).localizedStandardCompare(descriptor(for: rhs)) == .orderedAscending
        }
        events = snapshot.events.sorted { $0.timestamp > $1.timestamp }
        protectionEnabled = snapshot.settings.isEnabled

        if let selectedToolID, protectedTools.contains(where: { $0.id == selectedToolID }) {
            self.selectedToolID = selectedToolID
        } else {
            selectedToolID = protectedTools.first?.id
        }
    }

    private func runLoad(_ operation: () throws -> Void) async {
        isLoading = true
        defer { isLoading = false }

        do {
            try operation()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func runMutation(_ operation: () throws -> Void) async {
        isMutating = true
        defer { isMutating = false }

        do {
            try operation()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func openFilePanel(title: String, prompt: String, message: String) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.prompt = prompt
        panel.message = message
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.resolvesAliases = true
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        return panel.runModal() == .OK ? panel.url : nil
    }

    private func descriptor(for caller: AllowedCaller) -> String {
        var parts: [String] = []
        if let bundleID = caller.bundleID, !bundleID.isEmpty {
            parts.append(bundleID)
        }
        if let teamID = caller.teamID, !teamID.isEmpty {
            parts.append("Team \(teamID)")
        }
        if let path = caller.path, !path.isEmpty {
            parts.append(path)
        }
        if parts.isEmpty {
            parts.append(caller.id.uuidString)
        }
        return parts.joined(separator: " • ")
    }
}
