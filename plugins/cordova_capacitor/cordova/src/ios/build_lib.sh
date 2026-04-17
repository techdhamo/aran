#!/bin/bash

# ============================================
# IOS STATIC LIBRARY BUILD SCRIPT
# ============================================
# This script builds the ARAN RASP static library for iOS
# with symbol stripping and obfuscation
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
VERSION="1.0.0"
BUILD_DIR="build"
LIB_NAME="libaran_rasp.a"
RASP_CORE_DIR="../../../../../universal_rasp_core"

# Architectures
ARCHS="arm64 x86_64"

# ============================================
# FUNCTIONS
# ============================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================
# BUILD FOR SPECIFIC ARCHITECTURE
# ============================================

build_arch() {
    local ARCH=$1
    local SDK=$2
    
    log_info "Building for ${ARCH} (${SDK})..."
    
    local CC="clang"
    local CXX="clang++"
    local CFLAGS="-arch ${ARCH} -isysroot $(xcrun -sdk ${SDK} --show-sdk-path) -fvisibility=hidden -O3 -DNDEBUG"
    local CXXFLAGS="-arch ${ARCH} -isysroot $(xcrun -sdk ${SDK} --show-sdk-path) -fvisibility=hidden -O3 -DNDEBUG -std=c++17"
    local LDFLAGS="-arch ${ARCH}"
    
    local BUILD_DIR="${BUILD_DIR}/${ARCH}"
    local OBJ_DIR="${BUILD_DIR}/obj"
    
    mkdir -p "${OBJ_DIR}"
    
    # Compile universal RASP core
    if [ -f "${RASP_CORE_DIR}/universal_rasp_core.cpp" ]; then
        ${CXX} ${CXXFLAGS} -c "${RASP_CORE_DIR}/universal_rasp_core.cpp" -o "${OBJ_DIR}/universal_rasp_core.o"
    else
        log_warn "Universal RASP core not found, using stub implementation"
    fi
    
    # Compile iOS bridge
    if [ -f "ios_objcpp_bridge.mm" ]; then
        ${CXX} ${CXXFLAGS} -c "ios_objcpp_bridge.mm" -o "${OBJ_DIR}/ios_objcpp_bridge.o"
    fi
    
    # Create static library
    ar rcs "${BUILD_DIR}/${LIB_NAME}" ${OBJ_DIR}/*.o
    
    # Strip symbols
    strip -S "${BUILD_DIR}/${LIB_NAME}"
    
    log_info "Static library created: ${BUILD_DIR}/${LIB_NAME}"
}

# ============================================
# BUILD FOR ALL ARCHITECTURES
# ============================================

build_all() {
    log_info "Building ARAN RASP static library for iOS..."
    
    # Clean previous builds
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    
    # Build for arm64 (device)
    build_arch "arm64" "iphoneos"
    
    # Build for x86_64 (simulator)
    build_arch "x86_64" "iphonesimulator"
    
    # Create universal library
    log_info "Creating universal static library..."
    lipo -create \
        "${BUILD_DIR}/arm64/${LIB_NAME}" \
        "${BUILD_DIR}/x86_64/${LIB_NAME}" \
        -output "${BUILD_DIR}/universal/${LIB_NAME}"
    
    # Copy to src directory
    cp "${BUILD_DIR}/universal/${LIB_NAME}" "libaran_rasp.a"
    
    log_info "Universal static library created: libaran_rasp.a"
    
    # Cleanup
    rm -rf "${BUILD_DIR}"
    
    log_info "Build complete!"
}

# ============================================
# MAIN
# ============================================

case "${1:-}" in
    arm64)
        build_arch "arm64" "iphoneos"
        ;;
    x86_64)
        build_arch "x86_64" "iphonesimulator"
        ;;
    clean)
        rm -rf "${BUILD_DIR}"
        rm -f "libaran_rasp.a"
        log_info "Clean complete"
        ;;
    *)
        build_all
        ;;
esac
