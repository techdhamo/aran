#!/bin/bash
# Copyright 2024 Mazhai Technologies
# Licensed under the Apache License, Version 2.0

set -e

echo "🔨 Building Aran.framework..."

cd "$(dirname "$0")"

# Clean previous builds
rm -rf build/
rm -rf Aran.framework

# Build for device (arm64)
xcodebuild clean build \
    -project Aran/Aran.xcodeproj \
    -scheme Aran \
    -configuration Release \
    -sdk iphoneos \
    -arch arm64 \
    BUILD_DIR=build \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES

# Build for simulator (arm64, x86_64)
xcodebuild clean build \
    -project Aran/Aran.xcodeproj \
    -scheme Aran \
    -configuration Release \
    -sdk iphonesimulator \
    -arch arm64 -arch x86_64 \
    BUILD_DIR=build \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES

# Create XCFramework
xcodebuild -create-xcframework \
    -framework build/Release-iphoneos/Aran.framework \
    -framework build/Release-iphonesimulator/Aran.framework \
    -output Aran.xcframework

echo "✅ Aran.xcframework created successfully!"
echo "📦 Location: $(pwd)/Aran.xcframework"

# Also create single framework for demo app
cp -R build/Release-iphoneos/Aran.framework ./Aran.framework

echo "✅ Aran.framework created for demo app!"
echo "📦 Location: $(pwd)/Aran.framework"
