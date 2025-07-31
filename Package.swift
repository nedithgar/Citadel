// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Citadel",
    platforms: [
        .macOS(.v12),
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "Citadel",
            targets: ["Citadel"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/nedithgar/Joannis-swift-nio-ssh.git", from: "0.3.5"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.3"),
        .package(url: "https://github.com/mtynior/ColorizeSwift.git", from: "1.5.0"),
    ],
    targets: [
        .target(name: "CCitadelBcrypt"),
        .target(
            name: "Citadel",
            dependencies: [
                .target(name: "CCitadelBcrypt"),
                .product(name: "NIOSSH", package: "Joannis-swift-nio-ssh"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .executableTarget(
            name: "CitadelServerExample",
            dependencies: [
                "Citadel",
                .productItem(name: "ColorizeSwift", package: "ColorizeSwift")
            ]),
        .testTarget(
            name: "CitadelTests",
            dependencies: [
                "Citadel",
                .product(name: "NIOSSH", package: "Joannis-swift-nio-ssh"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
    ]
)
