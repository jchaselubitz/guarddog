import XCTest
@testable import GuardDogCore

final class PolicyEngineTests: XCTestCase {
    func testUnprotectedToolIsAllowed() {
        let engine = PolicyEngine()
        let result = engine.evaluate(
            request: ExecRequest(
                toolPath: "/usr/local/bin/other",
                caller: CallerIdentity(bundleID: "com.apple.Terminal", teamID: "TEAM1", executablePath: "/Applications/Terminal.app")
            ),
            settings: ProtectionSettings(isEnabled: true),
            protectedTools: [],
            allowedCallers: []
        )

        XCTAssertEqual(result.decision, .allow)
        XCTAssertEqual(result.reason, "tool is not protected")
    }

    func testProtectedToolWithoutAllowlistIsDenied() {
        let tool = ProtectedTool(path: "/usr/local/bin/claude")
        let engine = PolicyEngine()
        let result = engine.evaluate(
            request: ExecRequest(
                toolPath: "/usr/local/bin/claude",
                caller: CallerIdentity(bundleID: "com.example.Editor", teamID: "TEAM1", executablePath: "/Applications/Editor.app")
            ),
            settings: ProtectionSettings(isEnabled: true),
            protectedTools: [tool],
            allowedCallers: []
        )

        XCTAssertEqual(result.decision, .deny)
        XCTAssertEqual(result.reason, "caller is not on the allowlist for this tool")
    }

    func testBundleAndTeamMatchAllowsExecution() {
        let tool = ProtectedTool(path: "/usr/local/bin/claude")
        let caller = AllowedCaller(
            toolID: tool.id,
            bundleID: "com.apple.Terminal",
            teamID: "ABCDE12345"
        )
        let engine = PolicyEngine()
        let result = engine.evaluate(
            request: ExecRequest(
                toolPath: "/usr/local/bin/claude",
                caller: CallerIdentity(bundleID: "com.apple.Terminal", teamID: "ABCDE12345", executablePath: "/Applications/Terminal.app")
            ),
            settings: ProtectionSettings(isEnabled: true),
            protectedTools: [tool],
            allowedCallers: [caller]
        )

        XCTAssertEqual(result.decision, .allow)
        XCTAssertEqual(result.matchedCallerID, caller.id)
    }
}

final class FilePolicyStoreTests: XCTestCase {
    func testSnapshotRoundTrip() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let fileURL = directory.appendingPathComponent("policy.json")
        let lockURL = directory.appendingPathComponent("policy.lock")
        let store = try FilePolicyStore(fileURL: fileURL, lockURL: lockURL)

        let snapshot = PolicySnapshot(
            settings: ProtectionSettings(isEnabled: false),
            protectedTools: [ProtectedTool(path: "/usr/local/bin/claude")],
            allowedCallers: [AllowedCaller(toolID: UUID(), bundleID: "com.apple.Terminal", teamID: "TEAM1")],
            events: [ExecEvent(
                timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                toolPath: "/usr/local/bin/claude",
                callerBundleID: "com.apple.Terminal",
                callerTeamID: "TEAM1",
                callerExecutablePath: "/Applications/Terminal.app",
                decision: .allow,
                reason: "matched"
            )]
        )

        try store.save(snapshot)
        let loaded = try store.load()

        XCTAssertEqual(loaded.settings, snapshot.settings)
        XCTAssertEqual(loaded.protectedTools.count, 1)
        XCTAssertEqual(loaded.allowedCallers.count, 1)
        XCTAssertEqual(loaded.events.count, 1)
    }
}

final class PolicyDaemonTests: XCTestCase {
    func testSeparateDaemonInstancesSeeSharedState() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let storeURL = directory.appendingPathComponent("policy.json")
        let lockURL = directory.appendingPathComponent("policy.lock")
        let storeA = try FilePolicyStore(fileURL: storeURL, lockURL: lockURL)
        let storeB = try FilePolicyStore(fileURL: storeURL, lockURL: lockURL)
        let daemonA = try PolicyDaemon(store: storeA)
        let daemonB = try PolicyDaemon(store: storeB)

        let tool = try daemonA.addProtectedTool(path: "/usr/local/bin/claude")
        _ = try daemonB.addAllowedCaller(
            toolReference: tool.id.uuidString,
            bundleID: "com.apple.Terminal",
            teamID: "ABCDE12345",
            path: nil
        )

        let event = try daemonA.log(
            request: ExecRequest(
                toolPath: "/usr/local/bin/claude",
                caller: CallerIdentity(bundleID: "com.apple.Terminal", teamID: "ABCDE12345", executablePath: "/Applications/Utilities/Terminal.app")
            )
        )

        XCTAssertEqual(event.decision, .allow)
        XCTAssertEqual(try daemonB.listEvents(limit: 1).count, 1)
    }
}

final class PolicyIPCTests: XCTestCase {
    func testXPCClientTalksToDaemonServer() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let configuration = PolicyClientConfiguration(
            storeURL: directory.appendingPathComponent("policy.json"),
            lockURL: directory.appendingPathComponent("policy.lock"),
            socketURL: directory.appendingPathComponent("daemon.sock")
        )
        let server = try PolicyXPCServer(configuration: configuration)
        server.activate()

        let client = XPCPolicyClient(listenerEndpoint: server.endpoint)
        let tool = try client.addProtectedTool(path: "/usr/local/bin/guarded", hash: nil, signingIdentity: nil)
        _ = try client.addAllowedCaller(toolReference: tool.id.uuidString, bundleID: "com.apple.Terminal", teamID: "ABCDE12345", path: nil)

        let event = try client.evaluateExec(
            ExecRequest(
                toolPath: "/usr/local/bin/guarded",
                caller: CallerIdentity(bundleID: "com.apple.Terminal", teamID: "ABCDE12345", executablePath: "/Applications/Utilities/Terminal.app")
            )
        )

        XCTAssertEqual(event.decision, .allow)
        XCTAssertEqual(try client.listProtectedTools().count, 1)
        XCTAssertEqual(try client.listEvents(limit: 10).count, 1)
    }

    func testSocketClientTalksToDaemonServer() throws {
        let socketURL = FileManager.default.temporaryDirectory.appendingPathComponent("guarddog-\(UUID().uuidString).sock")
        let configuration = PolicyClientConfiguration(
            storeURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString)-policy.json"),
            lockURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString)-policy.lock"),
            socketURL: socketURL
        )
        let server = try PolicySocketServer(configuration: configuration)
        let started = expectation(description: "socket server started")

        let serverThread = Thread {
            started.fulfill()
            try? server.serve()
        }
        serverThread.start()
        wait(for: [started], timeout: 1.0)

        for _ in 0..<20 where !FileManager.default.fileExists(atPath: socketURL.path) {
            Thread.sleep(forTimeInterval: 0.05)
        }

        let client = try SocketPolicyClient(configuration: configuration)
        let tool = try client.addProtectedTool(path: "/usr/local/bin/socket-guarded", hash: nil, signingIdentity: nil)
        let event = try client.evaluateExec(
            ExecRequest(
                toolPath: tool.path,
                caller: CallerIdentity(bundleID: "com.apple.Terminal", teamID: "ABCDE12345", executablePath: "/Applications/Utilities/Terminal.app")
            )
        )

        XCTAssertEqual(event.decision, .deny)
        XCTAssertEqual(try client.listEvents(limit: 10).count, 1)
    }
}
