import Foundation

public final class PolicyDaemon: @unchecked Sendable {
    private let store: PolicyStore
    private let engine: PolicyEngine

    public init(store: PolicyStore) throws {
        self.store = store
        self.engine = PolicyEngine()
        _ = try store.load()
    }

    public func isEnabled() throws -> Bool {
        try store.load().settings.isEnabled
    }

    public func setEnabled(_ enabled: Bool) throws {
        _ = try store.withExclusiveSnapshotAccess { snapshot in
            snapshot.settings.isEnabled = enabled
        }
    }

    public func snapshot() throws -> PolicySnapshot {
        try store.load()
    }

    public func listProtectedTools() throws -> [ProtectedTool] {
        try store.load().protectedTools.sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
    }

    public func addProtectedTool(path: String, hash: String? = nil, signingIdentity: String? = nil) throws -> ProtectedTool {
        let normalizedPath = Paths.normalized(path)
        return try store.withExclusiveSnapshotAccess { snapshot in
            if let existing = snapshot.protectedTools.first(where: { Paths.normalized($0.path) == normalizedPath }) {
                return existing
            }

            let tool = ProtectedTool(path: normalizedPath, hash: hash, signingIdentity: signingIdentity)
            snapshot.protectedTools.append(tool)
            return tool
        }
    }

    public func removeProtectedTool(reference: String) throws -> ProtectedTool? {
        try store.withExclusiveSnapshotAccess { snapshot in
            guard let index = Self.resolveProtectedToolIndex(reference: reference, snapshot: snapshot) else {
                return nil
            }

            let removed = snapshot.protectedTools.remove(at: index)
            snapshot.allowedCallers.removeAll { $0.toolID == removed.id }
            return removed
        }
    }

    public func listAllowedCallers(toolReference: String? = nil) throws -> [AllowedCaller] {
        let snapshot = try store.load()
        let toolID = toolReference.flatMap { Self.resolveToolID(reference: $0, snapshot: snapshot) }
        return snapshot.allowedCallers
            .filter { toolID == nil || $0.toolID == toolID }
            .sorted { $0.id.uuidString < $1.id.uuidString }
    }

    public func addAllowedCaller(
        toolReference: String,
        bundleID: String? = nil,
        teamID: String? = nil,
        path: String? = nil
    ) throws -> AllowedCaller {
        try store.withExclusiveSnapshotAccess { snapshot in
            guard let toolID = Self.resolveToolID(reference: toolReference, snapshot: snapshot) else {
                throw NSError(domain: "GuardDog", code: 1, userInfo: [NSLocalizedDescriptionKey: "tool not found"])
            }

            let caller = AllowedCaller(toolID: toolID, bundleID: bundleID, teamID: teamID, path: path.map(Paths.normalized))
            snapshot.allowedCallers.append(caller)
            return caller
        }
    }

    public func removeAllowedCaller(id: UUID) throws -> AllowedCaller? {
        try store.withExclusiveSnapshotAccess { snapshot in
            guard let index = snapshot.allowedCallers.firstIndex(where: { $0.id == id }) else {
                return nil
            }
            let removed = snapshot.allowedCallers.remove(at: index)
            return removed
        }
    }

    public func log(request: ExecRequest) throws -> ExecEvent {
        try store.withExclusiveSnapshotAccess { snapshot in
            let decision = engine.evaluate(
                request: request,
                settings: snapshot.settings,
                protectedTools: snapshot.protectedTools,
                allowedCallers: snapshot.allowedCallers
            )

            let event = ExecEvent(
                toolPath: Paths.normalized(request.toolPath),
                callerBundleID: request.caller.bundleID,
                callerTeamID: request.caller.teamID,
                callerExecutablePath: request.caller.executablePath.map(Paths.normalized),
                decision: decision.decision,
                reason: decision.reason,
                matchedCallerID: decision.matchedCallerID
            )
            snapshot.events.append(event)
            return event
        }
    }

    public func listEvents(limit: Int? = nil) throws -> [ExecEvent] {
        let ordered = try store.load().events.sorted { $0.timestamp > $1.timestamp }
        guard let limit, limit > 0 else { return ordered }
        return Array(ordered.prefix(limit))
    }

    public func summary() throws -> String {
        let snapshot = try store.load()
        let protectedCount = snapshot.protectedTools.count
        let allowedCount = snapshot.allowedCallers.count
        let eventCount = snapshot.events.count
        let mode = snapshot.settings.isEnabled ? "enabled" : "disabled"
        return "protection \(mode), \(protectedCount) protected tool(s), \(allowedCount) allowlist entry(ies), \(eventCount) logged event(s)"
    }

    private static func resolveToolID(reference: String, snapshot: PolicySnapshot) -> UUID? {
        if let uuid = UUID(uuidString: reference) {
            return snapshot.protectedTools.first(where: { $0.id == uuid })?.id
        }

        let normalized = Paths.normalized(reference)
        return snapshot.protectedTools.first(where: { Paths.normalized($0.path) == normalized })?.id
    }

    private static func resolveProtectedToolIndex(reference: String, snapshot: PolicySnapshot) -> Int? {
        if let uuid = UUID(uuidString: reference) {
            return snapshot.protectedTools.firstIndex(where: { $0.id == uuid })
        }

        let normalized = Paths.normalized(reference)
        return snapshot.protectedTools.firstIndex(where: { Paths.normalized($0.path) == normalized })
    }
}
