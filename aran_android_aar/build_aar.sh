#!/bin/bash

# ============================================
# AAR BUILD SCRIPT FOR ARAN RASP ENGINE
# ============================================
# This script builds the Android AAR and publishes it to Maven/NPM repositories
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
VERSION="1.0.0"
GROUP_ID="com.aran.security"
ARTIFACT_ID="rasp-core"
AAR_FILE="${ARTIFACT_ID}-${VERSION}.aar"

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
# BUILD AAR
# ============================================

build_aar() {
    log_info "Building AAR for version ${VERSION}..."
    
    # Build the AAR using Gradle
    ./gradlew assembleRelease
    
    log_info "AAR build complete"
}

# ============================================
# PUBLISH TO MAVEN
# ============================================

publish_maven() {
    log_info "Publishing to Maven repository..."
    
    # Publish to Maven repository
    ./gradlew publishReleasePublicationToMavenRepository
    
    log_info "Maven publish complete"
}

# ============================================
# COPY TO NPM DIRECTORY
# ============================================

copy_to_npm() {
    log_info "Copying AAR to NPM directory..."
    
    # Find the AAR file
    AAR_PATH=$(find . -name "${AAR_FILE}" -type f | head -n 1)
    
    if [ -z "$AAR_PATH" ]; then
        log_error "AAR file not found: ${AAR_FILE}"
        exit 1
    fi
    
    # Copy to npm directory
    cp "$AAR_PATH" npm/
    
    log_info "AAR copied to npm directory"
}

# ============================================
# PUBLISH TO NPM
# ============================================

publish_npm() {
    log_info "Publishing to NPM repository..."
    
    cd npm
    
    # Login to NPM registry
    npm login --registry=https://npm.aran-security.com
    
    # Publish to NPM
    npm publish --registry=https://npm.aran-security.com
    
    cd ..
    
    log_info "NPM publish complete"
}

# ============================================
# MAIN
# ============================================

case "${1:-}" in
    build)
        build_aar
        ;;
    maven)
        publish_maven
        ;;
    npm)
        copy_to_npm
        publish_npm
        ;;
    all)
        build_aar
        publish_maven
        copy_to_npm
        publish_npm
        ;;
    *)
        echo "Usage: $0 {build|maven|npm|all}"
        echo "  build  - Build AAR only"
        echo "  maven  - Publish to Maven only"
        echo "  npm    - Publish to NPM only"
        echo "  all    - Build and publish to both"
        exit 1
        ;;
esac

log_info "Build script completed successfully"
