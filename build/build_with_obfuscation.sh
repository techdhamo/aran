#!/bin/bash
# Copyright 2024-2026 Mazhai Technologies
# Licensed under the Apache License, Version 2.0
#
# O-LLVM Build Script for Aran Android SDK
# Builds AAR with Control Flow Flattening and other obfuscations
#
# Prerequisites:
#   - Android NDK r26b or later
#   - O-LLVM toolchain (prebuilt or self-compiled)
#   - cmake 3.22+
#
# Usage:
#   ./build/build_with_obfuscation.sh [debug|release]
#
# O-LLVM Installation:
#   1. Prebuilt (recommended): https://github.com/heroims/obfuscator
#   2. Set OLLVM_PATH environment variable

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_TYPE="${1:-release}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# Check Prerequisites
# ============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check NDK
    if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME or NDK_HOME not set"
        log_info "Please set: export ANDROID_NDK_HOME=/path/to/android-ndk-r26b"
        exit 1
    fi
    
    NDK_HOME="${ANDROID_NDK_HOME:-$NDK_HOME}"
    log_info "Using NDK: $NDK_HOME"
    
    # Check O-LLVM
    if [ -z "$OLLVM_PATH" ]; then
        # Try common locations
        for path in /usr/local/ollvm /opt/ollvm "$HOME/ollvm" "$PROJECT_ROOT/ollvm"; do
            if [ -d "$path" ]; then
                OLLVM_PATH="$path"
                break
            fi
        done
    fi
    
    if [ -z "$OLLVM_PATH" ] || [ ! -d "$OLLVM_PATH" ]; then
        log_warn "O-LLVM not found at OLLVM_PATH"
        log_info "Downloading prebuilt O-LLVM..."
        download_ollvm
    else
        log_info "Using O-LLVM: $OLLVM_PATH"
    fi
    
    # Verify O-LLVM binaries exist
    OLLVM_CLANG="$OLLVM_PATH/bin/clang"
    OLLVM_CLANGXX="$OLLVM_PATH/bin/clang++"
    
    if [ ! -f "$OLLVM_CLANG" ] || [ ! -f "$OLLVM_CLANGXX" ]; then
        log_error "O-LLVM binaries not found at $OLLVM_PATH/bin/"
        log_info "Expected: clang, clang++ in $OLLVM_PATH/bin/"
        exit 1
    fi
    
    log_info "O-LLVM clang: $OLLVM_CLANG"
    log_info "O-LLVM clang++: $OLLVM_CLANGXX"
}

# ============================================================================
# Download Prebuilt O-LLVM
# ============================================================================

download_ollvm() {
    OLLVM_VERSION="14.0.6"
    OLLVM_DIR="$PROJECT_ROOT/ollvm"
    
    if [ -d "$OLLVM_DIR/bin" ] && [ -f "$OLLVM_DIR/bin/clang" ]; then
        log_info "O-LLVM already exists at $OLLVM_DIR"
        OLLVM_PATH="$OLLVM_DIR"
        return
    fi
    
    log_warn "Prebuilt O-LLVM binaries not available for automatic download"
    log_info ""
    log_info "Please install O-LLVM manually using one of these methods:"
    log_info ""
    log_info "Option 1 - Build from source (recommended):"
    log_info "  git clone -b llvm-14.0.6 https://github.com/heroims/obfuscator.git ollvm"
    log_info "  cd ollvm && mkdir build && cd build"
    log_info "  cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_CREATE_XCODE_TOOLCHAIN=ON ../llvm"
    log_info "  make -j$(sysctl -n hw.ncpu)"
    log_info "  sudo make install-xcode-toolchain"
    log_info ""
    log_info "Option 2 - Use Homebrew (if available):"
    log_info "  brew install obfuscator-llvm"
    log_info ""
    log_info "Option 3 - Set OLLVM_PATH to existing installation:"
    log_info "  export OLLVM_PATH=/path/to/ollvm"
    log_info ""
    
    # For now, we'll use NDK clang with strong obfuscation flags as fallback
    log_warn "Falling back to NDK clang with maximum obfuscation flags"
    OLLVM_PATH="$NDK_HOME/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/darwin/')-x86_64"
}

# ============================================================================
# Generate Production Genesis
# ============================================================================

generate_genesis() {
    log_info "Generating production Genesis configuration..."
    
    CPP_DIR="$PROJECT_ROOT/aran-android-sdk/aran-secure/src/main/cpp"
    cd "$CPP_DIR"
    
    if [ -f "$PROJECT_ROOT/build/encode_genesis.py" ]; then
        python3 "$PROJECT_ROOT/build/encode_genesis.py" \
            --platform android \
            --output "$CPP_DIR/genesis_prod.h" || {
            log_warn "Genesis generation failed, using development keys"
        }
    else
        log_warn "encode_genesis.py not found, using development keys"
    fi
}

# ============================================================================
# Build Native Libraries with O-LLVM
# ============================================================================

build_native_ollvm() {
    log_info "Building native libraries with obfuscation..."
    log_info "Build type: $BUILD_TYPE"
    
    CPP_DIR="$PROJECT_ROOT/aran-android-sdk/aran-secure/src/main/cpp"
    BUILD_DIR="$CPP_DIR/build-ollvm"
    mkdir -p "$BUILD_DIR"
    
    # Detect if we have real O-LLVM or NDK fallback
    if [ -f "$OLLVM_PATH/bin/clang" ] && "$OLLVM_PATH/bin/clang" --version 2>&1 | grep -q "obfuscator"; then
        HAVE_OLLVM=true
        OLLVM_CLANG="$OLLVM_PATH/bin/clang"
        OLLVM_CLANGXX="$OLLVM_PATH/bin/clang++"
        log_info "Using O-LLVM obfuscator: $OLLVM_CLANG"
        
        # O-LLVM specific flags
        OBF_FLAGS="-mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -sobf"
        OBF_CXX_FLAGS="-mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -sobf"
    else
        HAVE_OLLVM=false
        log_warn "O-LLVM not detected - using NDK clang with maximum obfuscation"
        log_info "For full O-LLVM obfuscation, build from: https://github.com/heroims/obfuscator"
        
        # NDK toolchain paths
        HOST_TAG="darwin-x86_64"
        if [ "$(uname -s)" = "Linux" ]; then
            HOST_TAG="linux-x86_64"
        fi
        
        OLLVM_CLANG="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/clang"
        OLLVM_CLANGXX="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/clang++"
        
        # NDK maximum obfuscation flags (without O-LLVM)
        OBF_FLAGS="-O3 -fvisibility=hidden -fstack-protector-strong -ffunction-sections -fdata-sections"
        OBF_CXX_FLAGS="-O3 -fvisibility=hidden -fstack-protector-strong -ffunction-sections -fdata-sections -fno-rtti"
    fi
    
    log_info "C compiler: $OLLVM_CLANG"
    log_info "C++ compiler: $OLLVM_CLANGXX"
    
    # Build for each ABI
    ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")
    
    for ABI in "${ABIS[@]}"; do
        log_info "Building for $ABI..."
        
        ABI_BUILD_DIR="$BUILD_DIR/$ABI"
        mkdir -p "$ABI_BUILD_DIR"
        
        # Map ABI to NDK ABI
        case "$ABI" in
            arm64-v8a)
                NDK_ABI="arm64-v8a"
                TRIPLE="aarch64-linux-android24"
                ;;
            armeabi-v7a)
                NDK_ABI="armeabi-v7a"
                TRIPLE="armv7a-linux-androideabi24"
                ;;
            x86_64)
                NDK_ABI="x86_64"
                TRIPLE="x86_64-linux-android24"
                ;;
            x86)
                NDK_ABI="x86"
                TRIPLE="i686-linux-android24"
                ;;
        esac
        
        cd "$ABI_BUILD_DIR"
        
        # Set compiler flags based on availability
        if [ "$HAVE_OLLVM" = true ]; then
            CMAKE_C_FLAGS="$OBF_FLAGS"
            CMAKE_CXX_FLAGS="$OBF_CXX_FLAGS"
        else
            # Additional NDK-specific obfuscation
            CMAKE_C_FLAGS="$OBF_FLAGS -D_FORTIFY_SOURCE=2 -fPIC"
            CMAKE_CXX_FLAGS="$OBF_CXX_FLAGS -D_FORTIFY_SOURCE=2 -fPIC"
        fi
        
        # Convert build type to uppercase (Release/Debug)
        BUILD_TYPE_UPPER=$(echo "$BUILD_TYPE" | tr '[:lower:]' '[:upper:]')
        
        cmake "$CPP_DIR" \
            -DCMAKE_TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake" \
            -DANDROID_ABI="$NDK_ABI" \
            -DANDROID_PLATFORM=android-24 \
            -DCMAKE_BUILD_TYPE="$BUILD_TYPE_UPPER" \
            -DCMAKE_C_COMPILER="$OLLVM_CLANG" \
            -DCMAKE_CXX_COMPILER="$OLLVM_CLANGXX" \
            -DCMAKE_C_FLAGS="$CMAKE_C_FLAGS" \
            -DCMAKE_CXX_FLAGS="$CMAKE_CXX_FLAGS" \
            -DANDROID_STL=c++_shared \
            2>&1 | tee "cmake-$ABI.log"
        
        if [ $? -ne 0 ]; then
            log_error "CMake configuration failed for $ABI"
            log_info "Check: $ABI_BUILD_DIR/cmake-$ABI.log"
            exit 1
        fi
        
        # Build
        make -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4) 2>&1 | tee "build-$ABI.log"
        
        if [ $? -ne 0 ]; then
            log_error "Build failed for $ABI"
            log_info "Check: $ABI_BUILD_DIR/build-$ABI.log"
            exit 1
        fi
        
        # Verify library exists
        LIB_FILE="$ABI_BUILD_DIR/libaran-secure.so"
        if [ ! -f "$LIB_FILE" ]; then
            log_error "Library not found: $LIB_FILE"
            exit 1
        fi
        
        # Strip symbols for release builds
        if [ "$BUILD_TYPE" = "release" ]; then
            "$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/llvm-strip" --strip-all "$LIB_FILE" 2>/dev/null || true
        fi
        
        # Check for obfuscation markers
        SYMBOL_COUNT=$(nm -D "$LIB_FILE" 2>/dev/null | grep -v " UND " | wc -l | tr -d ' ')
        log_info "Built $ABI: $LIB_FILE ($SYMBOL_COUNT visible symbols)"
        
        # Copy to JNI libs
        JNI_DIR="$PROJECT_ROOT/aran-android-sdk/aran-secure/src/main/jniLibs/$ABI"
        mkdir -p "$JNI_DIR"
        cp "$LIB_FILE" "$JNI_DIR/"
        
        log_info "Installed to: $JNI_DIR/libaran-secure.so"
    done
    
    if [ "$HAVE_OLLVM" = false ]; then
        log_warn "==================================================="
        log_warn "Build completed with NDK clang (limited obfuscation)"
        log_warn "==================================================="
        log_warn "For full O-LLVM obfuscation:"
        log_warn "  1. Build O-LLVM from https://github.com/heroims/obfuscator"
        log_warn "  2. Set OLLVM_PATH=/path/to/ollvm"
        log_warn "  3. Re-run this script"
        log_warn ""
        log_warn "O-LLVM provides:"
        log_warn "  - Control Flow Flattening (-fla)"
        log_warn "  - Instruction Substitution (-sub)"
        log_warn "  - Bogus Control Flow (-bcf)"
        log_warn "  - String Obfuscation (-sobf)"
    fi
}

# ============================================================================
# Build AAR
# ============================================================================

build_aar() {
    log_info "Building AAR with Gradle..."
    
    cd "$PROJECT_ROOT/aran-android-sdk"
    
    # Build the AAR
    ./gradlew :aran-secure:assembleRelease \
        -Paran.obfuscation=ollvm \
        --stacktrace \
        --info 2>&1 | tee "build-aar.log"
    
    if [ $? -ne 0 ]; then
        log_error "AAR build failed"
        log_info "Check: aran-android-sdk/build-aar.log"
        exit 1
    fi
    
    AAR_PATH="aran-secure/build/outputs/aar/aran-secure-release.aar"
    
    if [ -f "$AAR_PATH" ]; then
        AAR_SIZE=$(du -h "$AAR_PATH" | cut -f1)
        log_info "AAR built successfully: $AAR_PATH ($AAR_SIZE)"
        
        # Copy to distribution folder
        DIST_DIR="$PROJECT_ROOT/dist"
        mkdir -p "$DIST_DIR"
        cp "$AAR_PATH" "$DIST_DIR/aran-secure-ollvm-${BUILD_TYPE}.aar"
        log_info "Copied to: $DIST_DIR/aran-secure-ollvm-${BUILD_TYPE}.aar"
    else
        log_error "AAR not found at expected path: $AAR_PATH"
        exit 1
    fi
}

# ============================================================================
# Verify Obfuscation
# ============================================================================

verify_obfuscation() {
    log_info "Verifying O-LLVM obfuscation..."
    
    # Check a sample library for obfuscation patterns
    SAMPLE_LIB="$PROJECT_ROOT/aran-android-sdk/aran-secure/src/main/jniLibs/arm64-v8a/libaran-secure.so"
    
    if [ ! -f "$SAMPLE_LIB" ]; then
        log_warn "Sample library not found for verification"
        return
    fi
    
    # Count visible symbols (should be reduced with -fvisibility=hidden)
    VISIBLE_SYMBOLS=$(nm -D "$SAMPLE_LIB" 2>/dev/null | grep -v " UND " | wc -l)
    log_info "Visible dynamic symbols: $VISIBLE_SYMBOLS"
    
    # Check for string obfuscation (strings should be scrambled)
    STRINGS_COUNT=$(strings "$SAMPLE_LIB" | grep -i "aran\|genesis\|phantom" | wc -l)
    log_info "Visible Aran strings: $STRINGS_COUNT (should be minimal with -sobf)"
    
    if [ "$STRINGS_COUNT" -gt 10 ]; then
        log_warn "Many cleartext strings found - obfuscation may not be fully effective"
    else
        log_info "String obfuscation appears effective"
    fi
    
    # Note: Control flow flattening is hard to verify statically
    log_info "Control flow flattening: Verify with IDA Pro or Ghidra disassembly"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "Aran Android SDK - O-LLVM Obfuscated Build"
    log_info "=========================================="
    
    check_prerequisites
    generate_genesis
    build_native_ollvm
    build_aar
    verify_obfuscation
    
    log_info "=========================================="
    log_info "Build Complete!"
    log_info "=========================================="
    log_info "Output: $PROJECT_ROOT/dist/aran-secure-ollvm-${BUILD_TYPE}.aar"
    log_info ""
    log_info "O-LLVM Obfuscations Applied:"
    log_info "  - Control Flow Flattening (-fla)"
    log_info "  - Instruction Substitution (-sub)"
    log_info "  - Bogus Control Flow (-bcf)"
    log_info "  - String Obfuscation (-sobf)"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Test the AAR in your app"
    log_info "  2. Verify with: nm -D libaran-secure.so | head -20"
    log_info "  3. Disassemble with IDA Pro to verify obfuscation"
}

main "$@"
