# ARAN Maven Repository Infrastructure Guide

This guide explains how to set up a self-hosted Maven repository for ARAN dependencies, SDKs, and APIs with support for both generic and client-specific repositories.

## Table of Contents

1. [Repository Architecture](#repository-architecture)
2. [Repository Options](#repository-options)
3. [Nexus Repository Manager Setup](#nexus-repository-manager-setup)
4. [Repository Structure](#repository-structure)
5. [Authentication & Security](#authentication--security)
6. [CI/CD Integration](#cicd-integration)
7. [Client-Specific Repositories](#client-specific-repositories)

---

## Repository Architecture

### Multi-Tier Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   ARAN Maven Repository                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Releases   │  │  Snapshots   │  │   Private    │ │
│  │  (Generic)   │  │  (Generic)   │  │ (Client-Spec) │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Client A   │  │   Client B   │  │   Client C   │ │
│  │  Repository  │  │  Repository  │  │  Repository  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Repository Types

- **Generic Repositories**: Shared across all clients
  - `aran-releases` - Stable releases for all clients
  - `aran-snapshots` - Development builds for all clients

- **Client-Specific Repositories**: Isolated per client
  - `aran-client-a` - Client A specific artifacts
  - `aran-client-b` - Client B specific artifacts
  - `aran-client-c` - Client C specific artifacts

---

## Repository Options

### Option 1: Sonatype Nexus Repository Manager (Recommended)

**Pros:**
- Industry standard for Maven repositories
- Supports multiple repository types (Maven, npm, Docker, etc.)
- Built-in authentication and authorization
- Excellent UI and API
- Free OSS version available

**Cons:**
- Requires Java to run
- Resource intensive for large deployments

### Option 2: JFrog Artifactory

**Pros:**
- Enterprise-grade features
- Excellent Docker support
- Advanced replication and clustering
- Strong integration with CI/CD

**Cons:**
- Commercial license required for enterprise features
- More complex setup

### Option 3: AWS CodeArtifact

**Pros:**
- Fully managed AWS service
- No infrastructure maintenance
- Integrated with AWS ecosystem
- Pay-as-you-go pricing

**Cons:**
- AWS-specific
- Learning curve for AWS console

### Option 4: Self-Hosted Simple Maven (For Small Deployments)

**Pros:**
- Lightweight
- No external dependencies
- Easy to set up

**Cons:**
- Limited features
- No UI
- Manual management

---

## Nexus Repository Manager Setup

### Installation (Docker - Recommended)

```bash
# Pull Nexus image
docker pull sonatype/nexus3:latest

# Run Nexus container
docker run -d -p 8081:8081 \
  --name nexus \
  -v nexus-data:/nexus-data \
  sonatype/nexus3:latest
```

### Initial Setup

1. Access Nexus at `http://localhost:8081`
2. Sign in with default credentials:
   - Username: `admin`
   - Password: Check `/nexus-data/admin.password` in container
3. Configure initial admin password
4. Enable anonymous access (optional, for public artifacts)

### Repository Configuration

#### Create Generic Repositories

**Releases Repository:**
- Name: `aran-releases`
- Type: `maven2 (hosted)`
- Layout: `maven2`
- Version policy: `Release`
- Write policy: `Allow write once`

**Snapshots Repository:**
- Name: `aran-snapshots`
- Type: `maven2 (hosted)`
- Layout: `maven2`
- Version policy: `Snapshot`
- Write policy: `Allow overwrite`

#### Create Client-Specific Repositories

For each client (A, B, C, etc.):

```bash
# Client A Repository
- Name: `aran-client-a`
- Type: `maven2 (hosted)`
- Layout: `maven2`
- Version policy: `Release`
- Write policy: `Allow write once`

# Repeat for Client B, C, etc.
```

#### Create Repository Groups

Create a group repository to aggregate all repositories:

```bash
- Name: `aran-public`
- Type: `maven2 (group)`
- Members: 
  - aran-releases
  - aran-snapshots
  - aran-client-a (if public access needed)
  - aran-client-b (if public access needed)
```

---

## Repository Structure

### Directory Structure

```
nexus-data/
├── repositories/
│   ├── aran-releases/           # Generic releases
│   │   └── com/
│   │       └── aran/
│   │           └── security/
│   │               ├── rasp-core/
│   │               │   └── 1.0.0/
│   │               │       ├── rasp-core-1.0.0.aar
│   │               │       ├── rasp-core-1.0.0.pom
│   │               │       └── rasp-core-1.0.0-sources.jar
│   │               └── sdk/
│   │                   └── 1.0.0/
│   │                       └── sdk-1.0.0.aar
│   │
│   ├── aran-snapshots/          # Generic snapshots
│   │   └── com/
│   │       └── aran/
│   │           └── security/
│   │               └── rasp-core/
│   │                   └── 1.0.1-SNAPSHOT/
│   │
│   ├── aran-client-a/           # Client A specific
│   │   └── com/
│   │       └── aran/
│   │           └── client/
│   │               └── a/
│   │                   └── custom-sdk/
│   │                       └── 1.0.0/
│   │
│   └── aran-client-b/           # Client B specific
│       └── com/
│           └── aran/
│               └── client/
│                   └── b/
│                       └── custom-sdk/
│                           └── 1.0.0/
```

### Maven Coordinates

**Generic Artifacts:**
```
groupId: com.aran.security
artifactId: rasp-core
version: 1.0.0
```

**Client-Specific Artifacts:**
```
groupId: com.aran.client.a
artifactId: custom-sdk
version: 1.0.0
```

---

## Authentication & Security

### Nexus User Management

#### Create Generic User (For Generic Repositories)

```bash
Username: aran-generic
Role: nx-deployment
Permissions: Read/Write on aran-releases, aran-snapshots
```

#### Create Client-Specific Users

```bash
Username: aran-client-a
Role: nx-deployment
Permissions: Read/Write on aran-client-a only

Username: aran-client-b
Role: nx-deployment
Permissions: Read/Write on aran-client-b only
```

#### Create Read-Only User (For Client Consumption)

```bash
Username: aran-read-only
Role: nx-view
Permissions: Read on all repositories
```

### Environment Variables

```bash
# Generic repository access
export ARAN_MAVEN_USERNAME=aran-generic
export ARAN_MAVEN_PASSWORD=your-password

# Client-specific access
export ARAN_CLIENT_A_USERNAME=aran-client-a
export ARAN_CLIENT_A_PASSWORD=client-a-password

# Read-only access
export ARAN_READ_ONLY_USERNAME=aran-read-only
export ARAN_READ_ONLY_PASSWORD=read-only-password
```

---

## CI/CD Integration

### Gradle Configuration for Publishing

#### Generic Repository Publishing

```gradle
// build.gradle
publishing {
    publications {
        maven(MavenPublication) {
            groupId = 'com.aran.security'
            artifactId = 'rasp-core'
            version = '1.0.0'
            
            from components.android
        }
    }
    
    repositories {
        maven {
            url = 'https://maven.aran-security.com/repository/aran-releases/'
            credentials {
                username = System.getenv('ARAN_MAVEN_USERNAME')
                password = System.getenv('ARAN_MAVEN_PASSWORD')
            }
        }
    }
}
```

#### Client-Specific Repository Publishing

```gradle
// client-a/build.gradle
publishing {
    publications {
        maven(MavenPublication) {
            groupId = 'com.aran.client.a'
            artifactId = 'custom-sdk'
            version = '1.0.0'
            
            from components.android
        }
    }
    
    repositories {
        maven {
            url = 'https://maven.aran-security.com/repository/aran-client-a/'
            credentials {
                username = System.getenv('ARAN_CLIENT_A_USERNAME')
                password = System.getenv('ARAN_CLIENT_A_PASSWORD')
            }
        }
    }
}
```

### GitHub Actions CI/CD Pipeline

```yaml
# .github/workflows/publish-to-maven.yml
name: Publish to Maven Repository

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up JDK
        uses: actions/setup-java@v3
        with:
          java-version: '17'
          distribution: 'temurin'
      
      - name: Grant execute permission for gradlew
        run: chmod +x gradlew
      
      - name: Publish to Maven
        env:
          ARAN_MAVEN_USERNAME: ${{ secrets.ARAN_MAVEN_USERNAME }}
          ARAN_MAVEN_PASSWORD: ${{ secrets.ARAN_MAVEN_PASSWORD }}
        run: ./gradlew publish
```

---

## Client-Specific Repositories

### Repository Isolation Strategy

#### Option 1: Separate Repositories per Client

Each client gets their own hosted repository:
- `aran-client-a`
- `aran-client-b`
- `aran-client-c`

**Pros:**
- Complete isolation
- Custom permissions per client
- Separate versioning per client

**Cons:**
- More repositories to manage
- Potential duplication

#### Option 2: Single Repository with Client Prefix

Single repository with client-specific package names:
- `com.aran.security.rasp-core` (generic)
- `com.aran.client.a.sdk` (client A)
- `com.aran.client.b.sdk` (client B)

**Pros:**
- Fewer repositories
- Easier to manage
- Consistent structure

**Cons:**
- Less isolation
- Need careful permission management

#### Option 3: Repository Groups with Filtering

Create repository groups with client-specific filtering:
- `aran-group-a` - Includes generic + client A
- `aran-group-b` - Includes generic + client B
- `aran-group-c` - Includes generic + client C

**Pros:**
- Flexible access control
- Reuses generic artifacts
- Easy to add new clients

**Cons:**
- More complex configuration
- Need to manage groups

### Client Configuration

#### Client A Configuration

```gradle
// Client A's build.gradle
repositories {
    maven {
        url = 'https://maven.aran-security.com/repository/aran-group-a/'
        credentials {
            username = System.getenv('ARAN_CLIENT_A_USERNAME')
            password = System.getenv('ARAN_CLIENT_A_PASSWORD')
        }
    }
}

dependencies {
    // Generic artifacts (accessible to all clients)
    implementation 'com.aran.security:rasp-core:1.0.0@aar'
    
    // Client-specific artifacts (only Client A)
    implementation 'com.aran.client.a:custom-sdk:1.0.0@aar'
}
```

#### Client B Configuration

```gradle
// Client B's build.gradle
repositories {
    maven {
        url = 'https://maven.aran-security.com/repository/aran-group-b/'
        credentials {
            username = System.getenv('ARAN_CLIENT_B_USERNAME')
            password = System.getenv('ARAN_CLIENT_B_PASSWORD')
        }
    }
}

dependencies {
    // Generic artifacts (accessible to all clients)
    implementation 'com.aran.security:rasp-core:1.0.0@aar'
    
    // Client-specific artifacts (only Client B)
    implementation 'com.aran.client.b:custom-sdk:1.0.0@aar'
}
```

---

## Cloud-Native Update Strategy

### Version-Based Updates

1. **Semantic Versioning**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Version Ranges**: Allow clients to specify version ranges
3. **Automated Updates**: CI/CD pipeline automatically publishes new versions

### Client-Specific Overrides

```gradle
// Client A can override generic version
dependencies {
    // Use Client A specific version
    implementation 'com.aran.security:rasp-core:1.0.1@aar'
}
```

### Update Notification System

Implement a webhook/notification system:
1. New artifact published → Notify clients
2. Security update → Force update
3. Feature update → Optional update

---

## Monitoring & Analytics

### Nexus Metrics

- Repository size
- Download count per artifact
- Bandwidth usage
- Access logs
- Error rates

### Client Usage Tracking

```bash
# Enable Nexus analytics
# Track which clients download which artifacts
# Monitor version adoption rates
# Identify deprecated versions
```

---

## Disaster Recovery

### Backup Strategy

```bash
# Backup Nexus data
docker exec nexus tar -czf /nexus-data-backup.tar.gz /nexus-data

# Schedule regular backups
# Store backups in secure location
# Test restore procedures
```

### High Availability

- Set up Nexus clustering
- Use load balancer
- Implement failover mechanism
- Geographic distribution

---

## Security Best Practices

1. **HTTPS Only**: Always use HTTPS for repository access
2. **Strong Authentication**: Use strong passwords and API tokens
3. **Least Privilege**: Grant minimum required permissions
4. **Audit Logs**: Enable and monitor audit logs
5. **Regular Updates**: Keep Nexus updated with security patches
6. **Network Isolation**: Restrict network access as needed
7. **Secret Management**: Use proper secret management (Vault, AWS Secrets Manager)

---

## Cost Optimization

### Nexus OSS vs Pro

- **OSS**: Free, suitable for most use cases
- **Pro**: Paid, includes advanced features (clustering, replication, etc.)

### Storage Optimization

- Enable artifact cleanup
- Use compression
- Implement retention policies
- Monitor storage usage

---

## Troubleshooting

### Common Issues

**Authentication Failure:**
- Verify credentials
- Check user permissions
- Ensure correct repository URL

**Artifact Not Found:**
- Verify artifact coordinates
- Check repository selection
- Ensure artifact was published successfully

**Slow Downloads:**
- Check network connectivity
- Enable CDN caching
- Consider geographic distribution

---

## Summary

Setting up a self-hosted Maven repository for ARAN involves:

1. **Choose Repository Manager**: Nexus (recommended), Artifactory, or AWS CodeArtifact
2. **Configure Repositories**: Generic (releases/snapshots) + Client-Specific
3. **Set Up Authentication**: Create users with appropriate permissions
4. **Integrate CI/CD**: Automate publishing pipeline
5. **Implement Security**: HTTPS, strong authentication, audit logs
6. **Monitor Usage**: Track downloads, version adoption, storage
7. **Plan for Disaster Recovery**: Backup strategy, high availability

This architecture enables cloud-native updates without app redeployment, similar to antivirus definition updates.
