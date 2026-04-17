#!/bin/bash
set -e

echo "🔨 Building Aran.framework (simple build)..."

cd "$(dirname "$0")/Aran"

# Clean
rm -rf build/
xcodebuild clean -project Aran.xcodeproj -scheme Aran

# Build for simulator only (faster for demo)
xcodebuild build \
    -project Aran.xcodeproj \
    -scheme Aran \
    -configuration Debug \
    -sdk iphonesimulator \
    -derivedDataPath build

echo "✅ Framework built!"
echo "📦 Location: $(pwd)/build/Build/Products/Debug-iphonesimulator/Aran.framework"

# Copy to parent directory for demo app
cp -R build/Build/Products/Debug-iphonesimulator/Aran.framework ../Aran.framework

echo "✅ Copied to: $(cd .. && pwd)/Aran.framework"
