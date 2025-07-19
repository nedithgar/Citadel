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
        // .package(path: "/Users/joannisorlandos/git/joannis/swift-nio-ssh"),
        .package(name: "swift-nio-ssh", url: "https://github.com/Joannis/swift-nio-ssh.git", "0.3.4" ..< "0.4.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.3"),
        .package(url: "https://github.com/mtynior/ColorizeSwift.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "Citadel",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
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
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
    ]
)
