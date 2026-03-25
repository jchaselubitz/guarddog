import Foundation

public struct DecisionResult: Equatable, Sendable {
    public var decision: ExecDecision
    public var reason: String
    public var matchedCallerID: UUID?

    public init(decision: ExecDecision, reason: String, matchedCallerID: UUID? = nil) {
        self.decision = decision
        self.reason = reason
        self.matchedCallerID = matchedCallerID
    }
}

public final class PolicyEngine: Sendable {
    public init() {}

    public func evaluate(
        request: ExecRequest,
        settings: ProtectionSettings,
        protectedTools: [ProtectedTool],
        allowedCallers: [AllowedCaller]
    ) -> DecisionResult {
        guard settings.isEnabled else {
            return DecisionResult(decision: .allow, reason: "protection disabled")
        }

        let normalizedToolPath = Paths.normalized(request.toolPath)
        guard let protectedTool = protectedTools.first(where: { Paths.normalized($0.path) == normalizedToolPath }) else {
            return DecisionResult(decision: .allow, reason: "tool is not protected")
        }

        let caller = request.caller
        if let matched = allowedCallers.first(where: { $0.toolID == protectedTool.id && Self.matches(caller: caller, rule: $0) }) {
            return DecisionResult(
                decision: .allow,
                reason: Self.reason(for: matched, caller: caller),
                matchedCallerID: matched.id
            )
        }

        return DecisionResult(
            decision: .deny,
            reason: "caller is not on the allowlist for this tool"
        )
    }

    private static func matches(caller: CallerIdentity, rule: AllowedCaller) -> Bool {
        if let bundleID = rule.bundleID, let callerBundleID = caller.bundleID,
           bundleID.caseInsensitiveCompare(callerBundleID) == .orderedSame {
            if let teamID = rule.teamID {
                guard let callerTeamID = caller.teamID,
                      teamID.caseInsensitiveCompare(callerTeamID) == .orderedSame else {
                    return false
                }
            }
            return true
        }

        if let path = rule.path,
           let callerPath = caller.executablePath,
           Paths.normalized(path) == Paths.normalized(callerPath) {
            return true
        }

        return false
    }

    private static func reason(for rule: AllowedCaller, caller: CallerIdentity) -> String {
        if let bundleID = rule.bundleID {
            let teamComponent = rule.teamID.map { " and team \($0)" } ?? ""
            return "matched allowlist entry for bundle \(bundleID)\(teamComponent)"
        }
        if let path = rule.path, caller.executablePath != nil {
            return "matched allowlist path \(Paths.normalized(path))"
        }
        return "matched allowlist entry"
    }
}
