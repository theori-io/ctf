// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "zipviewer-version-clown",
    platforms: [
       .macOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", exact: "4.89.0"),
        .package(url: "https://github.com/vapor/leaf.git", exact: "4.2.4"),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", exact: "0.9.18"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "Leaf", package: "leaf"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(name: "AppTests", dependencies: [
            .target(name: "App"),
            .product(name: "XCTVapor", package: "vapor"),
            .product(name: "Vapor", package: "vapor"),
            .product(name: "Leaf", package: "leaf"),
        ])
    ]
)
