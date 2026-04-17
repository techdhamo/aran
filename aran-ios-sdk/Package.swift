// swift-tools-version:5.5
// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

import PackageDescription

let package = Package(
    name: "Aran",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "Aran",
            targets: ["Aran"]
        )
    ],
    targets: [
        .target(
            name: "Aran",
            path: "Aran/Sources",
            publicHeadersPath: "."
        )
    ],
    swiftLanguageVersions: [.v5]
)
