#!/bin/bash
# Copyright 2024 Mazhai Technologies
# Licensed under the Apache License, Version 2.0
#
# Builds Aran.xcframework with device (arm64) + simulator (arm64, x86_64) slices
# Builds universal XCFramework with device + simulator slices

set -e

echo "🔨 Building Aran.xcframework..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/Aran"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_DIR="$SCRIPT_DIR"

# Clean previous builds
rm -rf "$BUILD_DIR"
rm -rf "$OUTPUT_DIR/Aran.xcframework"
rm -rf "$OUTPUT_DIR/Aran.framework"

# Build for device (arm64)
echo "📱 Building for device (arm64)..."
xcodebuild build \
    -project "$PROJECT_DIR/Aran.xcodeproj" \
    -scheme Aran \
    -configuration Release \
    -sdk iphoneos \
    -derivedDataPath "$BUILD_DIR/device" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    ONLY_ACTIVE_ARCH=NO

# Build for simulator (arm64 + x86_64)
echo "🖥️  Building for simulator (arm64 + x86_64)..."
xcodebuild build \
    -project "$PROJECT_DIR/Aran.xcodeproj" \
    -scheme Aran \
    -configuration Release \
    -sdk iphonesimulator \
    -derivedDataPath "$BUILD_DIR/simulator" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    ONLY_ACTIVE_ARCH=NO

DEVICE_FRAMEWORK="$BUILD_DIR/device/Build/Products/Release-iphoneos/Aran.framework"
SIM_FRAMEWORK="$BUILD_DIR/simulator/Build/Products/Release-iphonesimulator/Aran.framework"

# Add PrivacyInfo.xcprivacy for App Store submission
cat > /tmp/PrivacyInfo.xcprivacy << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array/>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeDeviceID</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <false/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
            </array>
        </dict>
    </array>
    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>CA92.1</string>
            </array>
        </dict>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>C617.1</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
EOF

cp /tmp/PrivacyInfo.xcprivacy "$DEVICE_FRAMEWORK/PrivacyInfo.xcprivacy"
cp /tmp/PrivacyInfo.xcprivacy "$SIM_FRAMEWORK/PrivacyInfo.xcprivacy"

# Create XCFramework
echo "📦 Creating XCFramework..."
xcodebuild -create-xcframework \
    -framework "$DEVICE_FRAMEWORK" \
    -framework "$SIM_FRAMEWORK" \
    -output "$OUTPUT_DIR/Aran.xcframework"

echo ""
echo "✅ Aran.xcframework created successfully!"
echo "📦 Location: $OUTPUT_DIR/Aran.xcframework"
echo ""

# Also copy simulator framework for quick demo builds
cp -R "$SIM_FRAMEWORK" "$OUTPUT_DIR/Aran.framework"
echo "✅ Aran.framework (simulator) copied for demo app"

# Print structure
echo ""
echo "📂 XCFramework structure:"
find "$OUTPUT_DIR/Aran.xcframework" -maxdepth 3 -type f | head -20

# Cleanup
rm -rf "$BUILD_DIR"
rm -f /tmp/PrivacyInfo.xcprivacy

echo ""
echo "🎉 Build complete!"
