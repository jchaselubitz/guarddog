import Foundation
import Darwin

public protocol PolicyStore: Sendable {
    func load() throws -> PolicySnapshot
    func save(_ snapshot: PolicySnapshot) throws
    func withExclusiveSnapshotAccess<T>(_ body: (inout PolicySnapshot) throws -> T) throws -> T
}

public final class FilePolicyStore: PolicyStore, @unchecked Sendable {
    private let fileURL: URL
    private let lockURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileURL: URL? = nil, lockURL: URL? = nil) throws {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            self.fileURL = try Paths.policyStoreURL()
        }
        self.lockURL = try lockURL ?? Paths.policyLockURL()

        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601

        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func load() throws -> PolicySnapshot {
        try withFileLock {
            try readSnapshot()
        }
    }

    public func save(_ snapshot: PolicySnapshot) throws {
        try withFileLock {
            try writeSnapshot(snapshot)
        }
    }

    public func withExclusiveSnapshotAccess<T>(_ body: (inout PolicySnapshot) throws -> T) throws -> T {
        try withFileLock {
            var snapshot = try readSnapshot()
            let result = try body(&snapshot)
            try writeSnapshot(snapshot)
            return result
        }
    }

    public var url: URL {
        fileURL
    }

    private func readSnapshot() throws -> PolicySnapshot {
        let fm = FileManager.default
        guard fm.fileExists(atPath: fileURL.path) else {
            return PolicySnapshot()
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(PolicySnapshot.self, from: data)
    }

    private func writeSnapshot(_ snapshot: PolicySnapshot) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try encoder.encode(snapshot)
        try data.write(to: fileURL, options: [.atomic])
    }

    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        let directory = lockURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        defer {
            flock(descriptor, LOCK_UN)
            close(descriptor)
        }

        guard flock(descriptor, LOCK_EX) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        return try body()
    }
}
