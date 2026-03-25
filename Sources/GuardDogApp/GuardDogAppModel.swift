import AppKit
import Foundation
import GuardDogCore
import GuardDogExtension
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
    var showingCLIPicker = false
    var extensionStatus: ExtensionStatus = .stopped

    private var endpointExtension: EndpointSecurityExtension?

    enum ExtensionStatus: Equatable {
        case stopped
        case running
        case failed(String)

        var displayText: String {
            switch self {
            case .stopped: "Stopped"
            case .running: "Enforcing"
            case .failed(let msg): "Error: \(msg)"
            }
        }

        var isRunning: Bool { self == .running }
    }

    func activateExtension() {
        guard endpointExtension == nil else { return }

        // es_new_client sends SIGKILL when the process lacks a valid (non-ad-hoc)
        // signature with the ES entitlement AND a provisioning profile from Apple.
        // We probe in a child process first so the main app is never killed.
        guard Self.probeEndpointSecurityAccess() else {
            extensionStatus = .failed(
                "Cannot create an EndpointSecurity client. "
                + "This requires a Developer ID signature with a provisioning profile "
                + "that includes com.apple.developer.endpoint-security.client "
                + "(request at developer.apple.com), or running with SIP disabled."
            )
            return
        }

        do {
            let ext = try EndpointSecurityExtension()
            try ext.activate()
            endpointExtension = ext
            extensionStatus = .running
        } catch {
            extensionStatus = .failed(error.localizedDescription)
        }
    }

    /// Spawns the GuardDogESProbe helper to test whether `es_new_client`
    /// succeeds. The probe is a separate executable so if the kernel sends
    /// SIGKILL (ad-hoc signature + SIP enabled), only the probe dies — not
    /// the main app.
    private static func probeEndpointSecurityAccess() -> Bool {
        // Look for the probe binary next to the app binary
        guard let appURL = Bundle.main.executableURL else { return false }
        let probeURL = appURL.deletingLastPathComponent().appendingPathComponent("GuardDogESProbe")

        guard FileManager.default.isExecutableFile(atPath: probeURL.path) else { return false }

        let process = Process()
        process.executableURL = probeURL
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

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

    func addProtectedTool() {
        showingCLIPicker = true
    }

    func addProtectedToolAtPath(_ path: String) async {
        showingCLIPicker = false
        await runMutation {
            let client = try PolicyClientFactory.make()
            let tool = try client.addProtectedTool(path: path, hash: nil, signingIdentity: nil)
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
