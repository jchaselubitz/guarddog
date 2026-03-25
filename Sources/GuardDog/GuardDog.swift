import Foundation
import GuardDogCore

@main
struct GuardDog {
    static func main() {
        do {
            let cli = try CLI(arguments: Array(CommandLine.arguments.dropFirst()))
            try cli.run()
        } catch {
            fputs("GuardDog: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

private struct CLI {
    enum Command {
        case help
        case daemonServe
        case status
        case enable
        case disable
        case toolAdd(path: String, hash: String?, signingIdentity: String?)
        case toolList
        case toolRemove(reference: String)
        case allowAdd(tool: String, bundleID: String?, teamID: String?, path: String?)
        case allowList(tool: String?)
        case allowRemove(id: String)
        case eventList(limit: Int?)
        case simulate(toolPath: String, bundleID: String?, teamID: String?, callerPath: String?)
    }

    private let command: Command

    init(arguments: [String]) throws {
        self.command = try Self.parse(arguments)
    }

    func run() throws {
        if case .daemonServe = command {
            let configuration = try PolicyClientConfiguration.default()
            let server = try PolicySocketServer(configuration: configuration)
            print("policy daemon listening on \(configuration.socketURL.path)")
            try server.serve()
            return
        }

        let configuration = try PolicyClientConfiguration.default()
        let client = try PolicyClientFactory.make(configuration: configuration)

        switch command {
        case .help:
            print(Self.usage)
        case .daemonServe:
            return
        case .status:
            print(try client.summary())
            print("store: \(configuration.storeURL.path)")
        case .enable:
            try client.setEnabled(true)
            print("protection enabled")
        case .disable:
            try client.setEnabled(false)
            print("protection disabled")
        case let .toolAdd(path, hash, signingIdentity):
            let tool = try client.addProtectedTool(path: path, hash: hash, signingIdentity: signingIdentity)
            print("protected tool saved: \(tool.id.uuidString) \(tool.path)")
        case .toolList:
            let tools = try client.listProtectedTools()
            guard !tools.isEmpty else {
                print("no protected tools")
                return
            }
            for tool in tools {
                var details: [String] = ["id=\(tool.id.uuidString)", "path=\(tool.path)"]
                if let hash = tool.hash { details.append("hash=\(hash)") }
                if let signingIdentity = tool.signingIdentity { details.append("signing=\(signingIdentity)") }
                print(details.joined(separator: " "))
            }
        case let .toolRemove(reference):
            if let removed = try client.removeProtectedTool(reference: reference) {
                print("removed protected tool: \(removed.id.uuidString) \(removed.path)")
            } else {
                print("protected tool not found")
            }
        case let .allowAdd(tool, bundleID, teamID, path):
            let caller = try client.addAllowedCaller(toolReference: tool, bundleID: bundleID, teamID: teamID, path: path)
            print("allowlist entry saved: \(caller.id.uuidString)")
        case let .allowList(tool):
            let callers = try client.listAllowedCallers(toolReference: tool)
            guard !callers.isEmpty else {
                print("no allowlist entries")
                return
            }
            for caller in callers {
                var details: [String] = ["id=\(caller.id.uuidString)", "tool=\(caller.toolID.uuidString)"]
                if let bundleID = caller.bundleID { details.append("bundle=\(bundleID)") }
                if let teamID = caller.teamID { details.append("team=\(teamID)") }
                if let path = caller.path { details.append("path=\(path)") }
                print(details.joined(separator: " "))
            }
        case let .allowRemove(id):
            guard let uuid = UUID(uuidString: id) else {
                throw NSError(domain: "GuardDog", code: 2, userInfo: [NSLocalizedDescriptionKey: "allowlist entry id must be a UUID"])
            }
            if let removed = try client.removeAllowedCaller(id: uuid) {
                print("removed allowlist entry: \(removed.id.uuidString)")
            } else {
                print("allowlist entry not found")
            }
        case let .eventList(limit):
            let events = try client.listEvents(limit: limit)
            guard !events.isEmpty else {
                print("no events")
                return
            }
            for event in events {
                let callerBits = [
                    event.callerBundleID.map { "bundle=\($0)" },
                    event.callerTeamID.map { "team=\($0)" },
                    event.callerExecutablePath.map { "path=\($0)" }
                ].compactMap { $0 }.joined(separator: " ")
                let matched = event.matchedCallerID.map { " matched=\($0.uuidString)" } ?? ""
                print("[\(Formatting.format(event.timestamp))] \(event.decision.rawValue.uppercased()) tool=\(event.toolPath) \(callerBits) reason=\"\(event.reason)\"\(matched)")
            }
        case let .simulate(toolPath, bundleID, teamID, callerPath):
            let event = try client.evaluateExec(
                ExecRequest(
                    toolPath: toolPath,
                    caller: CallerIdentity(bundleID: bundleID, teamID: teamID, executablePath: callerPath)
                )
            )
            print("\(event.decision.rawValue.uppercased()) reason=\"\(event.reason)\"")
        }
    }

    private static let usage = """
    GuardDog - CLI execution control prototype

    Usage:
      GuardDog daemon serve
      GuardDog status
      GuardDog enable | disable
      GuardDog tool add <path> [--hash <value>] [--signing <identity>]
      GuardDog tool list
      GuardDog tool remove <id-or-path>
      GuardDog allow add --tool <id-or-path> [--bundle-id <id>] [--team-id <id>] [--path <app-path>]
      GuardDog allow list [--tool <id-or-path>]
      GuardDog allow remove <uuid>
      GuardDog event list [--limit <n>]
      GuardDog simulate --tool <path> [--bundle-id <id>] [--team-id <id>] [--caller-path <path>]
    """

    private static func parse(_ arguments: [String]) throws -> Command {
        guard let first = arguments.first else { return .help }

        switch first {
        case "help", "--help", "-h":
            return .help
        case "daemon":
            return try parseDaemon(Array(arguments.dropFirst()))
        case "status":
            return .status
        case "enable":
            return .enable
        case "disable":
            return .disable
        case "tool":
            return try parseTool(Array(arguments.dropFirst()))
        case "allow":
            return try parseAllow(Array(arguments.dropFirst()))
        case "event", "events", "log":
            return try parseEvents(Array(arguments.dropFirst()))
        case "simulate":
            return try parseSimulate(Array(arguments.dropFirst()))
        default:
            return .help
        }
    }

    private static func parseDaemon(_ arguments: [String]) throws -> Command {
        guard let action = arguments.first else { return .help }
        switch action {
        case "serve":
            return .daemonServe
        default:
            return .help
        }
    }

    private static func parseTool(_ arguments: [String]) throws -> Command {
        guard let action = arguments.first else { return .help }
        let rest = Array(arguments.dropFirst())

        switch action {
        case "add":
            guard let path = rest.first else { throw usageError("tool add requires a path") }
            let options = try Options(Array(rest.dropFirst()))
            return .toolAdd(path: path, hash: options["hash"], signingIdentity: options["signing"])
        case "list":
            return .toolList
        case "remove":
            guard let reference = rest.first else { throw usageError("tool remove requires a reference") }
            return .toolRemove(reference: reference)
        default:
            return .help
        }
    }

    private static func parseAllow(_ arguments: [String]) throws -> Command {
        guard let action = arguments.first else { return .help }
        let rest = Array(arguments.dropFirst())

        switch action {
        case "add":
            let options = try Options(rest)
            guard let tool = options["tool"] else { throw usageError("allow add requires --tool") }
            return .allowAdd(
                tool: tool,
                bundleID: options["bundle-id"],
                teamID: options["team-id"],
                path: options["path"]
            )
        case "list":
            let options = try Options(rest)
            return .allowList(tool: options["tool"])
        case "remove":
            guard let id = rest.first else { throw usageError("allow remove requires a UUID") }
            return .allowRemove(id: id)
        default:
            return .help
        }
    }

    private static func parseEvents(_ arguments: [String]) throws -> Command {
        let options = try Options(arguments)
        if let limit = options["limit"] {
            guard let parsed = Int(limit) else { throw usageError("--limit must be an integer") }
            return .eventList(limit: parsed)
        }
        return .eventList(limit: nil)
    }

    private static func parseSimulate(_ arguments: [String]) throws -> Command {
        let options = try Options(arguments)
        guard let toolPath = options["tool"] else { throw usageError("simulate requires --tool") }
        return .simulate(
            toolPath: toolPath,
            bundleID: options["bundle-id"],
            teamID: options["team-id"],
            callerPath: options["caller-path"]
        )
    }

    private struct Options {
        private var values: [String: String] = [:]

        init(_ arguments: [String]) throws {
            var iterator = arguments.makeIterator()
            while let key = iterator.next() {
                guard key.hasPrefix("--") else {
                    throw usageError("unexpected argument: \(key)")
                }
                guard let value = iterator.next(), !value.hasPrefix("--") else {
                    throw usageError("missing value for \(key)")
                }
                values[String(key.dropFirst(2))] = value
            }
        }

        subscript(key: String) -> String? {
            values[key]
        }
    }

    private static func usageError(_ message: String) -> Error {
        NSError(domain: "GuardDog", code: 3, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
