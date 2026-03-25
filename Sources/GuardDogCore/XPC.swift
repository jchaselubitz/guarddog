import Foundation

@objc public protocol PolicyXPCServiceProtocol {
    func send(_ requestData: Data, withReply reply: @escaping (Data?, String?) -> Void)
}

public final class PolicyXPCService: NSObject, PolicyXPCServiceProtocol {
    private let daemon: PolicyDaemon
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(daemon: PolicyDaemon) {
        self.daemon = daemon
        super.init()
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func send(_ requestData: Data, withReply reply: @escaping (Data?, String?) -> Void) {
        do {
            let request = try decoder.decode(PolicyIPCRequest.self, from: requestData)
            let response = try handle(request)
            reply(try encoder.encode(response), nil)
        } catch {
            reply(nil, error.localizedDescription)
        }
    }

    private func handle(_ request: PolicyIPCRequest) throws -> PolicyIPCResponse {
        switch request {
        case .summary:
            return .summary(try daemon.summary())
        case .snapshot:
            return .snapshot(try daemon.snapshot())
        case let .setEnabled(enabled):
            try daemon.setEnabled(enabled)
            return .ok
        case .listProtectedTools:
            return .protectedTools(try daemon.listProtectedTools())
        case let .addProtectedTool(draft):
            return .protectedTool(
                try daemon.addProtectedTool(
                    path: draft.path,
                    hash: draft.hash,
                    signingIdentity: draft.signingIdentity
                )
            )
        case let .removeProtectedTool(reference):
            return .removedProtectedTool(try daemon.removeProtectedTool(reference: reference))
        case let .listAllowedCallers(toolReference):
            return .allowedCallers(try daemon.listAllowedCallers(toolReference: toolReference))
        case let .addAllowedCaller(draft):
            return .allowedCaller(
                try daemon.addAllowedCaller(
                    toolReference: draft.toolReference,
                    bundleID: draft.bundleID,
                    teamID: draft.teamID,
                    path: draft.path
                )
            )
        case let .removeAllowedCaller(id):
            return .removedAllowedCaller(try daemon.removeAllowedCaller(id: id))
        case let .evaluateExec(request):
            return .execEvent(try daemon.log(request: request))
        case let .listEvents(limit):
            return .events(try daemon.listEvents(limit: limit))
        }
    }
}

public final class PolicyXPCServer: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let exportedObject: PolicyXPCService

    public init(configuration: PolicyClientConfiguration? = nil) throws {
        let configuration = try configuration ?? .default()
        let store = try FilePolicyStore(fileURL: configuration.storeURL, lockURL: configuration.lockURL)
        let daemon = try PolicyDaemon(store: store)
        self.listener = NSXPCListener.anonymous()
        self.exportedObject = PolicyXPCService(daemon: daemon)
        super.init()
        listener.delegate = self
    }

    public var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }

    public func activate() {
        listener.resume()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: PolicyXPCServiceProtocol.self)
        newConnection.exportedObject = exportedObject
        newConnection.resume()
        return true
    }
}

public final class XPCPolicyClient: PolicyClient, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(listenerEndpoint endpoint: NSXPCListenerEndpoint) {
        connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: PolicyXPCServiceProtocol.self)
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        connection.resume()
    }

    deinit {
        connection.invalidate()
    }

    public func summary() throws -> String {
        guard case let .summary(summary) = try send(.summary) else {
            throw Self.unexpectedResponse()
        }
        return summary
    }

    public func snapshot() throws -> PolicySnapshot {
        guard case let .snapshot(snapshot) = try send(.snapshot) else {
            throw Self.unexpectedResponse()
        }
        return snapshot
    }

    public func setEnabled(_ enabled: Bool) throws {
        guard case .ok = try send(.setEnabled(enabled)) else {
            throw Self.unexpectedResponse()
        }
    }

    public func listProtectedTools() throws -> [ProtectedTool] {
        guard case let .protectedTools(tools) = try send(.listProtectedTools) else {
            throw Self.unexpectedResponse()
        }
        return tools
    }

    public func addProtectedTool(path: String, hash: String?, signingIdentity: String?) throws -> ProtectedTool {
        guard case let .protectedTool(tool) = try send(.addProtectedTool(.init(path: path, hash: hash, signingIdentity: signingIdentity))) else {
            throw Self.unexpectedResponse()
        }
        return tool
    }

    public func removeProtectedTool(reference: String) throws -> ProtectedTool? {
        guard case let .removedProtectedTool(tool) = try send(.removeProtectedTool(reference: reference)) else {
            throw Self.unexpectedResponse()
        }
        return tool
    }

    public func listAllowedCallers(toolReference: String?) throws -> [AllowedCaller] {
        guard case let .allowedCallers(callers) = try send(.listAllowedCallers(toolReference: toolReference)) else {
            throw Self.unexpectedResponse()
        }
        return callers
    }

    public func addAllowedCaller(toolReference: String, bundleID: String?, teamID: String?, path: String?) throws -> AllowedCaller {
        guard case let .allowedCaller(caller) = try send(.addAllowedCaller(.init(toolReference: toolReference, bundleID: bundleID, teamID: teamID, path: path))) else {
            throw Self.unexpectedResponse()
        }
        return caller
    }

    public func removeAllowedCaller(id: UUID) throws -> AllowedCaller? {
        guard case let .removedAllowedCaller(caller) = try send(.removeAllowedCaller(id: id)) else {
            throw Self.unexpectedResponse()
        }
        return caller
    }

    public func evaluateExec(_ request: ExecRequest) throws -> ExecEvent {
        guard case let .execEvent(event) = try send(.evaluateExec(request)) else {
            throw Self.unexpectedResponse()
        }
        return event
    }

    public func listEvents(limit: Int?) throws -> [ExecEvent] {
        guard case let .events(events) = try send(.listEvents(limit: limit)) else {
            throw Self.unexpectedResponse()
        }
        return events
    }

    private func send(_ request: PolicyIPCRequest) throws -> PolicyIPCResponse {
        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?

        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            responseError = error
            semaphore.signal()
        } as? PolicyXPCServiceProtocol
        guard let proxy else {
            throw NSError(domain: "GuardDog", code: 12, userInfo: [NSLocalizedDescriptionKey: "failed to connect to daemon"])
        }

        let requestData = try encoder.encode(request)

        proxy.send(requestData) { data, errorMessage in
            responseData = data
            if let errorMessage {
                responseError = NSError(domain: "GuardDog", code: 13, userInfo: [NSLocalizedDescriptionKey: errorMessage])
            }
            semaphore.signal()
        }

        semaphore.wait()

        if let responseError {
            throw responseError
        }
        guard let responseData else {
            throw NSError(domain: "GuardDog", code: 14, userInfo: [NSLocalizedDescriptionKey: "daemon returned no response"])
        }
        return try decoder.decode(PolicyIPCResponse.self, from: responseData)
    }

    private static func unexpectedResponse() -> NSError {
        NSError(domain: "GuardDog", code: 15, userInfo: [NSLocalizedDescriptionKey: "daemon returned an unexpected response"])
    }
}
