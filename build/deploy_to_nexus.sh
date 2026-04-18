#!/bin/bash
# Copyright 2024-2026 Mazhai Technologies
# Licensed under the Apache License, Version 2.0
#
# Deploy AAR to Nexus Maven Repository

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AAR_FILE="${1:-$PROJECT_ROOT/dist/aran-secure-ollvm-release.aar}"
VERSION="${2:-1.0.0}"

# Nexus Configuration
NEXUS_URL="${NEXUS_URL:-https://maven.mazhai.org/nexus}"
REPOSITORY="${REPOSITORY:-aran-demobank}"
GROUP_ID="org.mazhai.aran"
ARTIFACT_ID="aran-secure"
USERNAME="${NEXUS_USERNAME:-admin}"
PASSWORD="${NEXUS_PASSWORD:-DS@n#2k22}"

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; }

# Validate AAR exists
if [ ! -f "$AAR_FILE" ]; then
    log_error "AAR file not found: $AAR_FILE"
    log_info "Usage: $0 [aar-file] [version]"
    exit 1
fi

log_info "Deploying AAR to Nexus..."
log_info "  File: $AAR_FILE"
log_info "  Version: $VERSION"
log_info "  Repository: $NEXUS_URL/repository/$REPOSITORY/"
log_info "  GAV: $GROUP_ID:$ARTIFACT_ID:$VERSION"

# Use Maven deploy:deploy-file or curl to upload
# Option 1: Using curl (no Maven required)
deploy_with_curl() {
    # Convert groupId dots to slashes for URL path
    local group_path=$(echo "$GROUP_ID" | tr '.' '/')    
    local url="$NEXUS_URL/repository/$REPOSITORY/$group_path/$ARTIFACT_ID/$VERSION/$ARTIFACT_ID-$VERSION.aar"
    
    log_info "Uploading to: $url"
    
    curl -v \
        --user "$USERNAME:$PASSWORD" \
        --upload-file "$AAR_FILE" \
        "$url" \
        2>&1 | tee /tmp/nexus_upload.log
    
    if [ $? -eq 0 ]; then
        log_info "Upload successful!"
        return 0
    else
        log_error "Upload failed"
        return 1
    fi
}

# Option 2: Using Maven (if available)
deploy_with_maven() {
    if ! command -v mvn &> /dev/null; then
        return 1
    fi
    
    mvn deploy:deploy-file \
        -DgroupId="$GROUP_ID" \
        -DartifactId="$ARTIFACT_ID" \
        -Dversion="$VERSION" \
        -Dpackaging=aar \
        -Dfile="$AAR_FILE" \
        -DrepositoryId="aran-nexus" \
        -Durl="$NEXUS_URL/repository/$REPOSITORY/" \
        -Dusername="$USERNAME" \
        -Dpassword="$PASSWORD"
}

# Try Maven first, fallback to curl
if deploy_with_maven; then
    log_info "Deployed using Maven"
elif deploy_with_curl; then
    log_info "Deployed using curl"
else
    log_error "All deployment methods failed"
    exit 1
fi

# Generate checksums for verification
log_info "Generating checksums..."
md5sum "$AAR_FILE" | awk '{print $1}' > "$AAR_FILE.md5"
sha1sum "$AAR_FILE" | awk '{print $1}' > "$AAR_FILE.sha1"
log_info "MD5: $(cat "$AAR_FILE.md5")"
log_info "SHA1: $(cat "$AAR_FILE.sha1")"

log_info "Deployment complete!"
log_info "AAR available at: $NEXUS_URL/repository/$REPOSITORY/$GROUP_ID/$ARTIFACT_ID/$VERSION/"
