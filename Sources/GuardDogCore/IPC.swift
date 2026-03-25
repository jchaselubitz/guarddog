import Foundation

public struct ProtectedToolDraft: Codable, Equatable, Sendable {
    public var path: String
    public var hash: String?
    public var signingIdentity: String?

    public init(path: String, hash: String? = nil, signingIdentity: String? = nil) {
        self.path = path
        self.hash = hash
        self.signingIdentity = signingIdentity
    }
}

public struct AllowedCallerDraft: Codable, Equatable, Sendable {
    public var toolReference: String
    public var bundleID: String?
    public var teamID: String?
    public var path: String?

    public init(
        toolReference: String,
        bundleID: String? = nil,
        teamID: String? = nil,
        path: String? = nil
    ) {
        self.toolReference = toolReference
        self.bundleID = bundleID
        self.teamID = teamID
        self.path = path
    }
}

public enum PolicyIPCRequest: Codable, Equatable, Sendable {
    case summary
    case snapshot
    case setEnabled(Bool)
    case listProtectedTools
    case addProtectedTool(ProtectedToolDraft)
    case removeProtectedTool(reference: String)
    case listAllowedCallers(toolReference: String?)
    case addAllowedCaller(AllowedCallerDraft)
    case removeAllowedCaller(id: UUID)
    case evaluateExec(ExecRequest)
    case listEvents(limit: Int?)
}

public enum PolicyIPCResponse: Codable, Equatable, Sendable {
    case summary(String)
    case snapshot(PolicySnapshot)
    case protectedTools([ProtectedTool])
    case protectedTool(ProtectedTool)
    case removedProtectedTool(ProtectedTool?)
    case allowedCallers([AllowedCaller])
    case allowedCaller(AllowedCaller)
    case removedAllowedCaller(AllowedCaller?)
    case execEvent(ExecEvent)
    case events([ExecEvent])
    case ok
}

public protocol PolicyClient: Sendable {
    func summary() throws -> String
    func snapshot() throws -> PolicySnapshot
    func setEnabled(_ enabled: Bool) throws
    func listProtectedTools() throws -> [ProtectedTool]
    func addProtectedTool(path: String, hash: String?, signingIdentity: String?) throws -> ProtectedTool
    func removeProtectedTool(reference: String) throws -> ProtectedTool?
    func listAllowedCallers(toolReference: String?) throws -> [AllowedCaller]
    func addAllowedCaller(toolReference: String, bundleID: String?, teamID: String?, path: String?) throws -> AllowedCaller
    func removeAllowedCaller(id: UUID) throws -> AllowedCaller?
    func evaluateExec(_ request: ExecRequest) throws -> ExecEvent
    func listEvents(limit: Int?) throws -> [ExecEvent]
}

public struct PolicyClientConfiguration: Sendable {
    public var storeURL: URL
    public var lockURL: URL
    public var socketURL: URL

    public init(storeURL: URL, lockURL: URL, socketURL: URL) {
        self.storeURL = storeURL
        self.lockURL = lockURL
        self.socketURL = socketURL
    }

    public static func `default`() throws -> PolicyClientConfiguration {
        PolicyClientConfiguration(
            storeURL: try Paths.policyStoreURL(),
            lockURL: try Paths.policyLockURL(),
            socketURL: try Paths.daemonSocketURL()
        )
    }
}

public enum PolicyClientFactory {
    public static func make(configuration: PolicyClientConfiguration? = nil) throws -> PolicyClient {
        let configuration = try configuration ?? .default()
        if let socketClient = try? SocketPolicyClient(configuration: configuration) {
            return socketClient
        }
        return try LocalPolicyClient(configuration: configuration)
    }
}

public final class LocalPolicyClient: PolicyClient, @unchecked Sendable {
    private let daemon: PolicyDaemon

    public init(configuration: PolicyClientConfiguration? = nil) throws {
        let configuration = try configuration ?? .default()
        let store = try FilePolicyStore(fileURL: configuration.storeURL, lockURL: configuration.lockURL)
        self.daemon = try PolicyDaemon(store: store)
    }

    public func summary() throws -> String {
        try daemon.summary()
    }

    public func snapshot() throws -> PolicySnapshot {
        try daemon.snapshot()
    }

    public func setEnabled(_ enabled: Bool) throws {
        try daemon.setEnabled(enabled)
    }

    public func listProtectedTools() throws -> [ProtectedTool] {
        try daemon.listProtectedTools()
    }

    public func addProtectedTool(path: String, hash: String?, signingIdentity: String?) throws -> ProtectedTool {
        try daemon.addProtectedTool(path: path, hash: hash, signingIdentity: signingIdentity)
    }

    public func removeProtectedTool(reference: String) throws -> ProtectedTool? {
        try daemon.removeProtectedTool(reference: reference)
    }

    public func listAllowedCallers(toolReference: String?) throws -> [AllowedCaller] {
        try daemon.listAllowedCallers(toolReference: toolReference)
    }

    public func addAllowedCaller(toolReference: String, bundleID: String?, teamID: String?, path: String?) throws -> AllowedCaller {
        try daemon.addAllowedCaller(toolReference: toolReference, bundleID: bundleID, teamID: teamID, path: path)
    }

    public func removeAllowedCaller(id: UUID) throws -> AllowedCaller? {
        try daemon.removeAllowedCaller(id: id)
    }

    public func evaluateExec(_ request: ExecRequest) throws -> ExecEvent {
        try daemon.log(request: request)
    }

    public func listEvents(limit: Int?) throws -> [ExecEvent] {
        try daemon.listEvents(limit: limit)
    }
}
