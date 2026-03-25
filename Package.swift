// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "GuardDog",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "GuardDogCore",
            targets: ["GuardDogCore"]
        ),
        .library(
            name: "GuardDogExtension",
            targets: ["GuardDogExtension"]
        ),
        .executable(
            name: "GuardDogApp",
            targets: ["GuardDogApp"]
        ),
        .executable(
            name: "GuardDog",
            targets: ["GuardDog"]
        )
    ],
    targets: [
        .target(
            name: "GuardDogCore"
        ),
        .target(
            name: "GuardDogExtension",
            dependencies: ["GuardDogCore"]
        ),
        .executableTarget(
            name: "GuardDogApp",
            dependencies: ["GuardDogCore"]
        ),
        .executableTarget(
            name: "GuardDog",
            dependencies: ["GuardDogCore"]
        ),
        .testTarget(
            name: "GuardDogCoreTests",
            dependencies: ["GuardDogCore"]
        )
    ]
)
