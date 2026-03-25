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
            dependencies: ["GuardDogCore"],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"),
            ]
        ),
        .executableTarget(
            name: "GuardDogApp",
            dependencies: ["GuardDogCore", "GuardDogExtension"]
        ),
        .executableTarget(
            name: "GuardDogESProbe",
            dependencies: ["GuardDogExtension"],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"),
            ]
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
