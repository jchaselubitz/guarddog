import Foundation
import Darwin

public final class PolicySocketServer: @unchecked Sendable {
    private let socketURL: URL
    private let service: PolicyXPCService
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(configuration: PolicyClientConfiguration? = nil) throws {
        let configuration = try configuration ?? .default()
        let store = try FilePolicyStore(fileURL: configuration.storeURL, lockURL: configuration.lockURL)
        let daemon = try PolicyDaemon(store: store)
        self.socketURL = configuration.socketURL
        self.service = PolicyXPCService(daemon: daemon)
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func serve() throws {
        let socketFD = try Self.makeListeningSocket(at: socketURL)
        defer {
            close(socketFD)
            try? FileManager.default.removeItem(at: socketURL)
        }

        while true {
            let clientFD = accept(socketFD, nil, nil)
            if clientFD < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }

            do {
                try handleClient(clientFD)
            } catch {
                if let errorData = try? encoder.encode(SocketEnvelope.error(error.localizedDescription)) {
                    _ = try? Self.writeAll(data: errorData, to: clientFD)
                }
            }

            shutdown(clientFD, SHUT_RDWR)
            close(clientFD)
        }
    }

    private func handleClient(_ clientFD: Int32) throws {
        let requestData = try Self.readAll(from: clientFD)
        let request = try decoder.decode(PolicyIPCRequest.self, from: requestData)

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?
        service.send(try encoder.encode(request)) { data, errorMessage in
            responseData = data
            if let errorMessage {
                responseError = NSError(domain: "GuardDog", code: 31, userInfo: [NSLocalizedDescriptionKey: errorMessage])
            }
            semaphore.signal()
        }
        semaphore.wait()

        if let responseError {
            throw responseError
        }
        guard let responseData else {
            throw NSError(domain: "GuardDog", code: 32, userInfo: [NSLocalizedDescriptionKey: "daemon returned no response"])
        }

        try Self.writeAll(data: try encoder.encode(SocketEnvelope.response(responseData)), to: clientFD)
    }

    private static func makeListeningSocket(at url: URL) throws -> Int32 {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: url)

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = url.path
        let maxPathLength = MemoryLayout.size(ofValue: address.sun_path)
        guard path.utf8.count < maxPathLength else {
            close(socketFD)
            throw NSError(domain: "GuardDog", code: 33, userInfo: [NSLocalizedDescriptionKey: "socket path is too long"])
        }

        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            _ = path.withCString { source in
                strncpy(rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self), source, maxPathLength - 1)
            }
        }

        var socketAddress = address
        let bindResult = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(socketFD, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard bindResult == 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            close(socketFD)
            throw POSIXError(code)
        }

        guard listen(socketFD, 16) == 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            close(socketFD)
            throw POSIXError(code)
        }

        return socketFD
    }

    static func readAll(from fd: Int32) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)

        while true {
            let count = read(fd, &buffer, buffer.count)
            if count > 0 {
                data.append(buffer, count: count)
                continue
            }
            if count == 0 {
                return data
            }
            if errno == EINTR {
                continue
            }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    @discardableResult
    static func writeAll(data: Data, to fd: Int32) throws -> Int {
        var writtenTotal = 0
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var pointer = baseAddress.assumingMemoryBound(to: UInt8.self)
            var remaining = rawBuffer.count

            while remaining > 0 {
                let written = write(fd, pointer, remaining)
                if written > 0 {
                    writtenTotal += written
                    remaining -= written
                    pointer = pointer.advanced(by: written)
                    continue
                }
                if written < 0 && errno == EINTR {
                    continue
                }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        return writtenTotal
    }
}

public final class SocketPolicyClient: PolicyClient, @unchecked Sendable {
    private let socketURL: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(configuration: PolicyClientConfiguration? = nil) throws {
        let configuration = try configuration ?? .default()
        guard FileManager.default.fileExists(atPath: configuration.socketURL.path) else {
            throw NSError(domain: "GuardDog", code: 40, userInfo: [NSLocalizedDescriptionKey: "daemon socket is unavailable"])
        }
        self.socketURL = configuration.socketURL
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
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
        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer {
            shutdown(socketFD, SHUT_RDWR)
            close(socketFD)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = socketURL.path
        let maxPathLength = MemoryLayout.size(ofValue: address.sun_path)
        guard path.utf8.count < maxPathLength else {
            throw NSError(domain: "GuardDog", code: 41, userInfo: [NSLocalizedDescriptionKey: "socket path is too long"])
        }

        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            _ = path.withCString { source in
                strncpy(rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self), source, maxPathLength - 1)
            }
        }

        var socketAddress = address
        let connectResult = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                connect(socketFD, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        try PolicySocketServer.writeAll(data: try encoder.encode(request), to: socketFD)
        shutdown(socketFD, SHUT_WR)

        let envelopeData = try PolicySocketServer.readAll(from: socketFD)
        let envelope = try decoder.decode(SocketEnvelope.self, from: envelopeData)
        switch envelope {
        case let .response(responseData):
            return try decoder.decode(PolicyIPCResponse.self, from: responseData)
        case let .error(message):
            throw NSError(domain: "GuardDog", code: 42, userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    private static func unexpectedResponse() -> NSError {
        NSError(domain: "GuardDog", code: 43, userInfo: [NSLocalizedDescriptionKey: "daemon returned an unexpected response"])
    }
}

private enum SocketEnvelope: Codable {
    case response(Data)
    case error(String)
}
