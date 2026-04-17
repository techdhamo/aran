#!/bin/bash

# ============================================
# ARAN MAVEN REPOSITORY SETUP SCRIPT
# ============================================
# This script automates the setup of Nexus repositories for ARAN
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
NEXUS_URL="http://localhost:13221/nexus"
NEXUS_ADMIN_USER="admin"
NEXUS_ADMIN_PASSWORD="DS@n#2k22"

# Repository names
REPO_RELEASES="aran-releases"
REPO_SNAPSHOTS="aran-snapshots"
REPO_PUBLIC="aran-public"
REPO_DEMOBANK="aran-demobank"

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
# GET ADMIN PASSWORD
# ============================================

get_admin_password() {
    log_info "Retrieving Nexus admin password..."
    NEXUS_ADMIN_PASSWORD=$(docker exec aran-nexus cat /nexus-data/admin-password)
    log_info "Admin password retrieved"
}

# ============================================
# CREATE GENERIC REPOSITORIES
# ============================================

create_generic_repositories() {
    log_info "Creating generic repositories..."
    
    # Create releases repository
    curl -X POST "${NEXUS_URL}/service/rest/v1/repositories/maven2/hosted" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'${REPO_RELEASES}'",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "cleanup": {
                "policyNames": []
            },
            "maven": {
                "versionPolicy": "RELEASE",
                "layoutPolicy": "STRICT",
                "contentDisposition": "ATTACHMENT"
            }
        }'
    
    log_info "Created ${REPO_RELEASES} repository"
    
    # Create snapshots repository
    curl -X POST "${NEXUS_URL}/service/rest/v1/repositories/maven2/hosted" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'${REPO_SNAPSHOTS}'",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "cleanup": {
                "policyNames": []
            },
            "maven": {
                "versionPolicy": "SNAPSHOT",
                "layoutPolicy": "STRICT",
                "contentDisposition": "ATTACHMENT"
            }
        }'
    
    log_info "Created ${REPO_SNAPSHOTS} repository"
    
    # Create public group repository
    curl -X POST "${NEXUS_URL}/service/rest/v1/repositories/maven2/group" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'${REPO_PUBLIC}'",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "group": {
                "memberNames": [
                    "'${REPO_RELEASES}'",
                    "'${REPO_SNAPSHOTS}'"
                ]
            }
        }'
    
    log_info "Created ${REPO_PUBLIC} group repository"
}

# ============================================
# CREATE DEMOBANK REPOSITORY
# ============================================

create_demobank_repository() {
    log_info "Creating demobank repository..."
    
    curl -X POST "${NEXUS_URL}/service/rest/v1/repositories/maven2/hosted" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'${REPO_DEMOBANK}'",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "cleanup": {
                "policyNames": []
            },
            "maven": {
                "versionPolicy": "RELEASE",
                "layoutPolicy": "STRICT",
                "contentDisposition": "ATTACHMENT"
            }
        }'
    
    log_info "Created ${REPO_DEMOBANK} repository"
}

# ============================================
# CREATE CLIENT-SPECIFIC REPOSITORIES
# ============================================

create_client_repository() {
    local CLIENT_ID=$1
    
    log_info "Creating repository for client: ${CLIENT_ID}"
    
    curl -X POST "${NEXUS_URL}/service/rest/v1/repositories/maven2/hosted" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "aran-client-'${CLIENT_ID}'",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "cleanup": {
                "policyNames": []
            },
            "maven": {
                "versionPolicy": "RELEASE",
                "layoutPolicy": "STRICT",
                "contentDisposition": "ATTACHMENT"
            }
        }'
    
    log_info "Created aran-client-${CLIENT_ID} repository"
}

# ============================================
# CREATE USERS
# ============================================

create_user() {
    local USERNAME=$1
    local PASSWORD=$2
    local ROLE=$3
    local REPOS=$4
    
    log_info "Creating user: ${USERNAME}"
    
    curl -X POST "${NEXUS_URL}/service/rest/v1/security/users" \
        -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d '{
            "userId": "'${USERNAME}'",
            "firstName": "'${USERNAME}'",
            "lastName": "User",
            "email": "'${USERNAME}'@aran.mazhai.org",
            "password": "'${PASSWORD}'",
            "status": "active",
            "roles": ["nx-deployment"]
        }'
    
    log_info "Created user: ${USERNAME}"
}

# ============================================
# MAIN
# ============================================

main() {
    log_info "Starting ARAN Maven repository setup..."
    
    # Wait for Nexus to be ready
    log_info "Waiting for Nexus to be ready..."
    sleep 30
    
    # Create generic repositories
    create_generic_repositories
    
    # Create demobank repository
    create_demobank_repository
    
    # Create client-specific repositories
    create_client_repository "a"
    create_client_repository "b"
    create_client_repository "c"
    
    # Create users
    create_user "aran-generic" "generic-password" "nx-deployment" "aran-releases,aran-snapshots"
    create_user "aran-demobank" "demobank-password" "nx-deployment" "aran-demobank"
    create_user "aran-client-a" "client-a-password" "nx-deployment" "aran-client-a"
    create_user "aran-client-b" "client-b-password" "nx-deployment" "aran-client-b"
    create_user "aran-read-only" "read-only-password" "nx-view" "aran-releases,aran-snapshots,aran-client-a,aran-client-b"
    
    log_info "ARAN Maven repository setup completed successfully!"
    log_info "Nexus URL: ${NEXUS_URL}"
    log_info "Public repository: ${NEXUS_URL}/repository/${REPO_PUBLIC}/"
}

main "$@"
