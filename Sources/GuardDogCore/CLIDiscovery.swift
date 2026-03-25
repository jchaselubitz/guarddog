import Foundation

/// Represents a discovered CLI executable on the system.
public struct DiscoveredCLI: Identifiable, Hashable, Sendable {
    public var id: String { path }
    public let name: String
    public let path: String
    public let directory: String

    public init(name: String, path: String, directory: String) {
        self.name = name
        self.path = path
        self.directory = directory
    }
}

/// Discovers CLI executables installed on the system by scanning well-known directories.
public enum CLIDiscovery {

    /// Directories to scan for CLI executables, ordered by relevance.
    public static let defaultDirectories: [String] = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]

    /// Returns directories from the user's PATH that are not already in the default list.
    public static func additionalPATHDirectories() -> [String] {
        let defaults = Set(defaultDirectories)
        guard let pathValue = ProcessInfo.processInfo.environment["PATH"] else { return [] }
        return pathValue.split(separator: ":").map(String.init).filter { !defaults.contains($0) }
    }

    /// Scans the given directories for executable files and returns them as `DiscoveredCLI` values.
    public static func discover(in directories: [String]? = nil) -> [DiscoveredCLI] {
        let dirs = directories ?? (defaultDirectories + additionalPATHDirectories())
        let fm = FileManager.default
        var seen = Set<String>() // deduplicate by resolved path
        var results: [DiscoveredCLI] = []

        for dir in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let fullPath = (dir as NSString).appendingPathComponent(entry)

                // Resolve symlinks so we deduplicate correctly
                let resolved = (fullPath as NSString).resolvingSymlinksInPath
                guard !seen.contains(resolved) else { continue }

                // Must be a regular file (or symlink to one) and executable
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: fullPath, isDirectory: &isDir), !isDir.boolValue else { continue }
                guard fm.isExecutableFile(atPath: fullPath) else { continue }

                // Skip entries that look like non-CLI artifacts (e.g., shared libraries, config files with +x)
                let name = (fullPath as NSString).lastPathComponent
                if name.contains(".") {
                    let ext = (name as NSString).pathExtension.lowercased()
                    let skipExtensions: Set<String> = ["dylib", "so", "a", "py", "rb", "pl", "sh", "bash", "zsh", "fish", "jar", "app"]
                    if skipExtensions.contains(ext) { continue }
                }

                seen.insert(resolved)
                results.append(DiscoveredCLI(name: name, path: fullPath, directory: dir))
            }
        }

        results.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        return results
    }
}
