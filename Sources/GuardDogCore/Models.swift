import Foundation

public struct ProtectedTool: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    public var path: String
    public var hash: String?
    public var signingIdentity: String?

    public init(
        id: UUID = UUID(),
        path: String,
        hash: String? = nil,
        signingIdentity: String? = nil
    ) {
        self.id = id
        self.path = path
        self.hash = hash
        self.signingIdentity = signingIdentity
    }
}

public struct AllowedCaller: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    public var toolID: UUID
    public var bundleID: String?
    public var teamID: String?
    public var path: String?

    public init(
        id: UUID = UUID(),
        toolID: UUID,
        bundleID: String? = nil,
        teamID: String? = nil,
        path: String? = nil
    ) {
        self.id = id
        self.toolID = toolID
        self.bundleID = bundleID
        self.teamID = teamID
        self.path = path
    }
}

public enum ExecDecision: String, Codable, Sendable {
    case allow
    case deny
}

public struct CallerIdentity: Codable, Equatable, Sendable {
    public var bundleID: String?
    public var teamID: String?
    public var executablePath: String?

    public init(
        bundleID: String? = nil,
        teamID: String? = nil,
        executablePath: String? = nil
    ) {
        self.bundleID = bundleID
        self.teamID = teamID
        self.executablePath = executablePath
    }
}

public struct ExecRequest: Codable, Equatable, Sendable {
    public var toolPath: String
    public var caller: CallerIdentity

    public init(toolPath: String, caller: CallerIdentity) {
        self.toolPath = toolPath
        self.caller = caller
    }
}

public struct ExecEvent: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    public var timestamp: Date
    public var toolPath: String
    public var callerBundleID: String?
    public var callerTeamID: String?
    public var callerExecutablePath: String?
    public var decision: ExecDecision
    public var reason: String
    public var matchedCallerID: UUID?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        toolPath: String,
        callerBundleID: String?,
        callerTeamID: String?,
        callerExecutablePath: String?,
        decision: ExecDecision,
        reason: String,
        matchedCallerID: UUID? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.toolPath = toolPath
        self.callerBundleID = callerBundleID
        self.callerTeamID = callerTeamID
        self.callerExecutablePath = callerExecutablePath
        self.decision = decision
        self.reason = reason
        self.matchedCallerID = matchedCallerID
    }
}

public struct ProtectionSettings: Codable, Equatable, Sendable {
    public var isEnabled: Bool

    public init(isEnabled: Bool = true) {
        self.isEnabled = isEnabled
    }
}

public struct PolicySnapshot: Codable, Equatable, Sendable {
    public var settings: ProtectionSettings
    public var protectedTools: [ProtectedTool]
    public var allowedCallers: [AllowedCaller]
    public var events: [ExecEvent]

    public init(
        settings: ProtectionSettings = ProtectionSettings(),
        protectedTools: [ProtectedTool] = [],
        allowedCallers: [AllowedCaller] = [],
        events: [ExecEvent] = []
    ) {
        self.settings = settings
        self.protectedTools = protectedTools
        self.allowedCallers = allowedCallers
        self.events = events
    }
}

