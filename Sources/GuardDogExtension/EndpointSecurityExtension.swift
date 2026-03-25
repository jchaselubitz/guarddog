import EndpointSecurity
import Foundation
import GuardDogCore
import Security

public final class EndpointSecurityExtension {
    private let policyClient: PolicyClient
    private var client: OpaquePointer?

    public init(policyClient: PolicyClient? = nil, configuration: PolicyClientConfiguration? = nil) throws {
        if let policyClient {
            self.policyClient = policyClient
        } else {
            self.policyClient = try PolicyClientFactory.make(configuration: configuration)
        }
    }

    deinit {
        guard let client else { return }
        es_unsubscribe_all(client)
        es_delete_client(client)
    }

    public func activate() throws {
        guard client == nil else { return }

        let result = es_new_client(&client) { [weak self] rawClient, message in
            guard let self else {
                _ = es_respond_auth_result(rawClient, message, ES_AUTH_RESULT_ALLOW, false)
                return
            }
            self.handle(message: message, client: rawClient)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            throw EndpointSecurityError.clientCreationFailed(result)
        }

        var subscriptions = [ES_EVENT_TYPE_AUTH_EXEC]
        guard es_subscribe(client, &subscriptions, UInt32(subscriptions.count)) == ES_RETURN_SUCCESS else {
            throw EndpointSecurityError.subscriptionFailed
        }
    }

    private func handle(message: UnsafePointer<es_message_t>, client: OpaquePointer) {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC else {
            respondAllow(to: message, client: client, shouldCache: false)
            return
        }

        handleExec(message: message, client: client)
    }

    private func handleExec(message: UnsafePointer<es_message_t>, client: OpaquePointer) {
        do {
            let request = try makeExecRequest(from: message)
            let event = try policyClient.evaluateExec(request)
            let decision = event.decision == .allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            respond(to: message, client: client, result: decision, shouldCache: false)
        } catch {
            respondAllow(to: message, client: client, shouldCache: false)
        }
    }

    private func makeExecRequest(from message: UnsafePointer<es_message_t>) throws -> ExecRequest {
        let callerProcess = message.pointee.process.pointee
        let targetProcess = message.pointee.event.exec.target.pointee
        guard let toolPath = filePath(from: targetProcess.executable) else {
            throw EndpointSecurityError.missingTargetPath
        }
        let signingInformation = signingInformation(for: callerProcess)

        return ExecRequest(
            toolPath: toolPath,
            caller: CallerIdentity(
                bundleID: resolveBundleID(for: callerProcess, signingInformation: signingInformation),
                teamID: resolveTeamID(for: callerProcess, signingInformation: signingInformation),
                executablePath: filePath(from: callerProcess.executable)
            )
        )
    }

    private func resolveBundleID(for process: es_process_t, signingInformation: [String: Any]?) -> String? {
        signingInformation?[kSecCodeInfoIdentifier as String] as? String
            ?? string(from: process.signing_id)
    }

    private func resolveTeamID(for process: es_process_t, signingInformation: [String: Any]?) -> String? {
        string(from: process.team_id)
            ?? signingInformation?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private func signingInformation(for process: es_process_t) -> [String: Any]? {
        let pid = auditTokenPID(process.audit_token)
        guard pid > 0 else { return nil }

        let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
        var secCode: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &secCode)
        guard guestStatus == errSecSuccess, let secCode else {
            return nil
        }

        var staticCode: SecStaticCode?
        let staticCodeStatus = SecCodeCopyStaticCode(secCode, SecCSFlags(), &staticCode)
        guard staticCodeStatus == errSecSuccess, let staticCode else {
            return nil
        }

        var information: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(staticCode, SecCSFlags(), &information)
        guard infoStatus == errSecSuccess, let information else {
            return nil
        }

        return information as? [String: Any]
    }

    private func filePath(from file: UnsafePointer<es_file_t>?) -> String? {
        guard let file else { return nil }
        return string(from: file.pointee.path)
    }

    private func string(from token: es_string_token_t) -> String? {
        guard token.length > 0, let data = token.data else { return nil }
        let buffer = UnsafeBufferPointer(start: UnsafeRawPointer(data).assumingMemoryBound(to: UInt8.self), count: Int(token.length))
        return String(decoding: buffer, as: UTF8.self)
    }

    private func auditTokenPID(_ token: audit_token_t) -> pid_t {
        let values = withUnsafeBytes(of: token.val) { rawBuffer in
            rawBuffer.bindMemory(to: UInt32.self)
        }
        guard values.count > 5 else { return 0 }
        return pid_t(values[5])
    }

    private func respondAllow(to message: UnsafePointer<es_message_t>, client: OpaquePointer, shouldCache: Bool) {
        respond(to: message, client: client, result: ES_AUTH_RESULT_ALLOW, shouldCache: shouldCache)
    }

    private func respond(
        to message: UnsafePointer<es_message_t>,
        client: OpaquePointer,
        result: es_auth_result_t,
        shouldCache: Bool
    ) {
        _ = es_respond_auth_result(client, message, result, shouldCache)
    }
}

public enum EndpointSecurityError: LocalizedError {
    case clientCreationFailed(es_new_client_result_t)
    case subscriptionFailed
    case missingTargetPath

    public var errorDescription: String? {
        switch self {
        case let .clientCreationFailed(result):
            "failed to create Endpoint Security client: \(result.rawValue)"
        case .subscriptionFailed:
            "failed to subscribe to AUTH_EXEC events"
        case .missingTargetPath:
            "exec event did not include a target executable path"
        }
    }
}
