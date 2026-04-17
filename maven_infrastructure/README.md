# ARAN Maven Repository Infrastructure

This directory contains the Docker Compose configuration and scripts for setting up a self-hosted Maven repository for ARAN dependencies, SDKs, and APIs.

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- SSL certificates (for HTTPS)
- Domain name configured (maven.aran-security.com)

### Setup

1. **Generate SSL Certificates**

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=maven.aran-security.com"
```

2. **Start the Infrastructure**

```bash
docker-compose up -d
```

3. **Wait for Nexus to Initialize**

Nexus takes about 2-3 minutes to initialize. Check logs:

```bash
docker-compose logs -f nexus
```

4. **Run Repository Setup Script**

```bash
chmod +x scripts/setup_repositories.sh
./scripts/setup_repositories.sh
```

5. **Access Nexus**

- URL: `https://maven.aran-security.com`
- Admin password: Check `/nexus-data/admin-password` in container

```bash
docker exec aran-nexus cat /nexus-data/admin-password
```

## Repository Structure

### Generic Repositories

- `aran-releases` - Stable releases for all clients
- `aran-snapshots` - Development builds for all clients
- `aran-public` - Group repository aggregating generic repos

### Client-Specific Repositories

- `aran-client-a` - Client A specific artifacts
- `aran-client-b` - Client B specific artifacts
- `aran-client-c` - Client C specific artifacts

## Users

### Generic User

- Username: `aran-generic`
- Password: `generic-password`
- Access: Generic repositories only

### Client-Specific Users

- Username: `aran-client-a` / `aran-client-b` / `aran-client-c`
- Password: `client-a-password` / `client-b-password` / `client-c-password`
- Access: Client-specific repository only

### Read-Only User

- Username: `aran-read-only`
- Password: `read-only-password`
- Access: Read-only access to all repositories

## Usage in Projects

### Generic Repository Access

```gradle
repositories {
    maven {
        url 'https://maven.aran-security.com/repository/aran-public/'
        credentials {
            username = System.getenv('ARAN_MAVEN_USERNAME')
            password = System.getenv('ARAN_MAVEN_PASSWORD')
        }
    }
}

dependencies {
    implementation 'com.aran.security:rasp-core:1.0.0@aar'
}
```

### Client-Specific Repository Access

```gradle
repositories {
    maven {
        url 'https://maven.aran-security.com/repository/aran-client-a/'
        credentials {
            username = System.getenv('ARAN_CLIENT_A_USERNAME')
            password = System.getenv('ARAN_CLIENT_A_PASSWORD')
        }
    }
}

dependencies {
    implementation 'com.aran.client.a:custom-sdk:1.0.0@aar'
}
```

## Publishing Artifacts

### Publish to Generic Repository

```gradle
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

### Publish to Client-Specific Repository

```gradle
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

## Management

### Backup

Backups are automatically created daily in the `./backups` directory. Manual backup:

```bash
docker exec aran-nexus tar -czf /tmp/nexus-backup.tar.gz /nexus-data
docker cp aran-nexus:/tmp/nexus-backup.tar.gz ./backups/
```

### Restore

```bash
docker cp ./backups/nexus-backup-YYYYMMDD-HHMMSS.tar.gz aran-nexus:/tmp/
docker exec aran-nexus tar -xzf /tmp/nexus-backup-YYYYMMDD-HHMMSS.tar.gz -C /
```

### Logs

```bash
docker-compose logs nexus
docker-compose logs nginx
```

### Stop

```bash
docker-compose down
```

### Start

```bash
docker-compose up -d
```

## Security

- HTTPS is enforced via Nginx reverse proxy
- Security headers are configured
- Strong passwords should be used in production
- SSL certificates should be renewed before expiration
- Network access should be restricted via firewall rules

## Troubleshooting

### Nexus Not Starting

Check logs:
```bash
docker-compose logs nexus
```

Ensure sufficient disk space and memory.

### Cannot Access Nexus

- Check if containers are running: `docker-compose ps`
- Check Nginx configuration
- Verify SSL certificates
- Check firewall rules

### Authentication Failed

- Verify username and password
- Check user permissions in Nexus UI
- Ensure repository is accessible to the user

## Cloud-Native Updates

This setup enables cloud-native updates without app redeployment:

1. **Publish New Version**: Publish updated AAR to Maven repository
2. **Client Fetch**: Clients fetch new version at build time
3. **No App Update**: No need for app store approval
4. **Antivirus Model**: Similar to antivirus definition updates

## Support

For detailed setup instructions, see `../maven_repository_guide.md`
