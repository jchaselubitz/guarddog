import Foundation

enum Paths {
    static func normalized(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        return NSString(string: trimmed).standardizingPath
    }

    static func applicationSupportDirectory() throws -> URL {
        let fm = FileManager.default
        guard let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw CocoaError(.fileNoSuchFile)
        }
        let directory = base.appendingPathComponent("GuardDog", isDirectory: true)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    static func policyStoreURL() throws -> URL {
        try applicationSupportDirectory().appendingPathComponent("policy.json")
    }

    static func policyLockURL() throws -> URL {
        try applicationSupportDirectory().appendingPathComponent("policy.lock")
    }

    static func daemonEndpointURL() throws -> URL {
        try applicationSupportDirectory().appendingPathComponent("daemon.endpoint")
    }

    static func daemonSocketURL() throws -> URL {
        try applicationSupportDirectory().appendingPathComponent("daemon.sock")
    }
}
