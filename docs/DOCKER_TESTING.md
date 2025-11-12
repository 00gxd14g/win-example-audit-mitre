# Docker Testing Guide

This guide explains how to use Docker containers for testing Windows Event Log auditing configurations in an isolated, reproducible environment.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Docker Configuration](#docker-configuration)
- [Running Tests Locally](#running-tests-locally)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Overview

The Windows Audit Testing Docker environment provides:

- **Isolated Testing**: Test audit configurations without affecting host system
- **Reproducibility**: Consistent environment across development and CI/CD
- **Automation**: Automated testing with GitHub Actions
- **Safety**: Run potentially risky test scripts in containers
- **Portability**: Share and distribute test environments easily

## Prerequisites

### Local Development

1. **Windows 10/11 or Windows Server 2016+**
   - Docker Desktop for Windows
   - Windows containers enabled

2. **Docker Desktop Configuration**
   ```powershell
   # Switch to Windows containers
   & $Env:ProgramFiles\Docker\Docker\DockerCli.exe -SwitchWindowsEngine
   ```

3. **System Requirements**
   - 8GB RAM minimum (16GB recommended)
   - 50GB free disk space
   - Hyper-V or WSL2 enabled

### CI/CD (GitHub Actions)

- Repository with GitHub Actions enabled
- Windows runners available (GitHub-hosted or self-hosted)

## Quick Start

### Option 1: Using Helper Script (Recommended)

```powershell
# Navigate to project directory
cd win-example-audit-mitre

# Run all tests (build, start container, run tests)
.\scripts\Local-DockerTest.ps1 -Action All

# Or use specific actions
.\scripts\Local-DockerTest.ps1 -Action Build        # Build image only
.\scripts\Local-DockerTest.ps1 -Action Run          # Start container
.\scripts\Local-DockerTest.ps1 -Action Test         # Run tests
.\scripts\Local-DockerTest.ps1 -Action Shell        # Interactive shell
.\scripts\Local-DockerTest.ps1 -Action Stop         # Stop container
.\scripts\Local-DockerTest.ps1 -Action Clean        # Remove everything
```

### Option 2: Using Docker Commands Directly

```powershell
# Build the image
docker build -t win-audit-test:latest .

# Run the container
docker run -d --name windows-audit-testing win-audit-test:latest

# Execute tests
docker exec windows-audit-testing powershell -File C:\workspace\scripts\Run-DockerTests.ps1 -TestSuite All

# Copy results to host
docker cp windows-audit-testing:C:\test-results\. .\test-results\

# Clean up
docker stop windows-audit-testing
docker rm windows-audit-testing
```

### Option 3: Using Docker Compose

```powershell
# Start the container
docker-compose up -d

# Run tests
docker-compose exec windows-audit-test powershell -File C:\workspace\scripts\Run-DockerTests.ps1

# View logs
docker-compose logs -f

# Stop and remove
docker-compose down
```

## Docker Configuration

### Dockerfile

The `Dockerfile` configures a Windows Server Core container with:

- **Base Image**: `mcr.microsoft.com/windows/servercore:ltsc2022`
- **PowerShell**: Set as default shell
- **Event Log Service**: Enabled and running
- **Audit Policies**: Pre-configured for comprehensive logging
- **Registry Settings**: PowerShell logging enabled
- **Health Check**: Monitors Event Log service status

Key configuration layers:

```dockerfile
# Enable audit policies
RUN auditpol /set /category:"Object Access" /success:enable /failure:enable

# Enable PowerShell logging
RUN reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Configure Event Log sizes
RUN wevtutil sl Security /ms:67108864
```

### Docker Compose

The `docker-compose.yml` provides:

- **Persistent Volumes**: Bind mounts for scripts, tests, and results
- **Resource Limits**: CPU and memory constraints
- **Network**: Isolated NAT network
- **Environment Variables**: Configure test behavior

## Running Tests Locally

### Test Suites

The container supports multiple test suites:

1. **AuditConfig**: Validates audit policy and registry configuration
2. **EventGeneration**: Tests actual event creation and logging
3. **Synthetic**: Generates synthetic attack scenario logs
4. **Integration**: End-to-end testing of full audit pipeline
5. **All**: Runs all test suites

### Running Specific Test Suites

```powershell
# Run only audit configuration tests
.\scripts\Local-DockerTest.ps1 -Action Test -TestSuite AuditConfig

# Run event generation tests
docker exec windows-audit-testing powershell -File C:\workspace\scripts\Run-DockerTests.ps1 -TestSuite EventGeneration

# Run synthetic log generation
docker exec windows-audit-testing powershell -File C:\workspace\scripts\Run-DockerTests.ps1 -TestSuite Synthetic
```

### Interactive Testing

```powershell
# Open PowerShell session in container
.\scripts\Local-DockerTest.ps1 -Action Shell

# Or using docker directly
docker exec -it windows-audit-testing powershell

# Inside container, run commands manually
PS C:\workspace> .\scripts\win-audit.ps1
PS C:\workspace> .\scripts\Test-EventIDGeneration.ps1 -Verbose
PS C:\workspace> Get-WinEvent -LogName Security -MaxEvents 10
```

### Viewing Test Results

```powershell
# Results are saved in test-results/ directory
Get-ChildItem .\test-results\

# View JSON results
Get-Content .\test-results\test-results-*.json | ConvertFrom-Json

# Parse and display summary
$results = Get-Content .\test-results\test-results-*.json | ConvertFrom-Json
Write-Host "Passed: $($results.Summary.Passed)"
Write-Host "Failed: $($results.Summary.Failed)"
```

## CI/CD Integration

### GitHub Actions Workflows

The project includes two workflows:

#### 1. Full Test Suite (`windows-docker-tests.yml`)

Triggered on:
- Push to `main`, `develop`, or `claude/**` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch

Jobs:
- **Build**: Create Docker image
- **Test-Audit-Config**: Validate audit configuration
- **Test-Event-Generation**: Test event creation
- **Test-Synthetic-Logs**: Generate attack scenarios
- **Test-Integration**: End-to-end integration tests
- **Report**: Aggregate results and create summary

#### 2. Quick PR Test (`pr-quick-test.yml`)

Triggered on pull requests for fast validation:
- PowerShell syntax validation
- Dockerfile syntax check
- Documentation presence check
- Quick smoke tests

### Workflow Usage

```yaml
# Trigger manually with custom test suite
name: Custom Test Run
on: workflow_dispatch
  inputs:
    test_suite:
      description: 'Test suite to run'
      required: true
      default: 'All'
```

### Viewing CI Results

1. **GitHub Actions Tab**: View workflow runs
2. **Artifacts**: Download test results and logs
3. **PR Comments**: Automated test reports on PRs

## Troubleshooting

### Common Issues

#### 1. Docker Not Running

```
Error: Docker is not running or not accessible
```

**Solution**:
```powershell
# Start Docker Desktop
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

# Verify Docker is running
docker ps
```

#### 2. Wrong Container Mode

```
Error: image operating system "windows" cannot be used on this platform
```

**Solution**:
```powershell
# Switch to Windows containers
& $Env:ProgramFiles\Docker\Docker\DockerCli.exe -SwitchWindowsEngine
```

#### 3. Insufficient Resources

```
Error: container failed to start
```

**Solution**:
- Increase Docker Desktop memory limit (Settings > Resources)
- Close other applications to free resources
- Check disk space availability

#### 4. Event Log Access Denied

```
Error: Access denied when querying Event Log
```

**Solution**:
- Ensure container has proper isolation mode
- Run Docker Desktop as Administrator
- Check Windows container security settings

#### 5. Tests Failing in Container

```powershell
# Check container logs
docker logs windows-audit-testing

# Verify Event Log service
docker exec windows-audit-testing powershell Get-Service EventLog

# Check audit policies
docker exec windows-audit-testing powershell auditpol /get /category:*

# Verify registry settings
docker exec windows-audit-testing powershell Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

### Debug Mode

```powershell
# Run container with interactive shell
docker run -it --name debug-container win-audit-test:latest powershell

# Inside container, run commands step-by-step
PS C:\workspace> Get-Service EventLog
PS C:\workspace> auditpol /get /category:*
PS C:\workspace> .\scripts\Test-EventIDGeneration.ps1 -Verbose
```

## Advanced Usage

### Custom Container Configuration

```powershell
# Run with custom environment variables
docker run -d `
  --name custom-audit-test `
  -e AUDIT_MODE=comprehensive `
  -e ENABLE_DETAILED_LOGGING=true `
  win-audit-test:latest

# Run with additional volume mounts
docker run -d `
  --name audit-test-with-output `
  -v ${PWD}\custom-scripts:C:\custom `
  -v ${PWD}\output:C:\output `
  win-audit-test:latest
```

### Multi-Container Testing

```yaml
# docker-compose.yml with multiple test containers
services:
  comprehensive-test:
    image: win-audit-test:latest
    environment:
      - AUDIT_MODE=comprehensive

  optimized-test:
    image: win-audit-test:latest
    environment:
      - AUDIT_MODE=optimized
```

### Extending the Dockerfile

```dockerfile
# Add custom tools
RUN choco install -y sysinternals

# Copy additional scripts
COPY custom-scripts/ C:\custom\

# Run custom initialization
RUN powershell -File C:\custom\init.ps1
```

### Performance Tuning

```powershell
# Limit container resources
docker run -d `
  --name audit-test `
  --cpus="2" `
  --memory="4g" `
  win-audit-test:latest

# Use process isolation for better performance
docker run -d `
  --name audit-test `
  --isolation=process `
  win-audit-test:latest
```

## Best Practices

1. **Regular Cleanup**: Remove old containers and images
   ```powershell
   # Remove stopped containers
   docker container prune -f

   # Remove unused images
   docker image prune -f
   ```

2. **Version Control**: Tag images with versions
   ```powershell
   docker build -t win-audit-test:v1.0.0 .
   docker tag win-audit-test:v1.0.0 win-audit-test:latest
   ```

3. **Test Isolation**: Use separate containers for different test runs
   ```powershell
   docker run --name test-run-1 win-audit-test:latest
   docker run --name test-run-2 win-audit-test:latest
   ```

4. **Log Management**: Regularly export and clean logs
   ```powershell
   docker logs audit-test > audit-test.log
   docker logs audit-test --since 1h > recent.log
   ```

5. **Security**: Keep base images updated
   ```powershell
   # Pull latest base image
   docker pull mcr.microsoft.com/windows/servercore:ltsc2022

   # Rebuild with latest base
   docker build --no-cache -t win-audit-test:latest .
   ```

## Resources

- [Docker Documentation](https://docs.docker.com/)
- [Windows Container Documentation](https://docs.microsoft.com/en-us/virtualization/windowscontainers/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)

## Support

For issues and questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review container logs: `docker logs windows-audit-testing`
- Open an issue on GitHub with:
  - Container logs
  - Test results
  - System information (`docker info`, `docker version`)
