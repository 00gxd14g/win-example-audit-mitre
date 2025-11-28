<#
.SYNOPSIS
    Helper script for local Docker testing of Windows audit configuration

.DESCRIPTION
    This script provides a convenient interface for building, running, and testing
    the Windows audit Docker container locally. It automates common Docker operations
    and provides interactive testing capabilities.

.PARAMETER Action
    The action to perform:
    - Build: Build the Docker image
    - Run: Start a new container
    - Test: Run tests in existing container
    - Shell: Open interactive PowerShell in container
    - Stop: Stop and remove container
    - Clean: Remove container and image
    - All: Build, run, and test

.PARAMETER TestSuite
    Which test suite to run (default: All)

.PARAMETER Interactive
    Start container in interactive mode

.EXAMPLE
    .\Local-DockerTest.ps1 -Action Build
    Builds the Docker image

.EXAMPLE
    .\Local-DockerTest.ps1 -Action All
    Builds image, starts container, and runs all tests

.EXAMPLE
    .\Local-DockerTest.ps1 -Action Test -TestSuite EventGeneration
    Runs event generation tests in existing container

.NOTES
    Requires: Docker Desktop with Windows containers enabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Build', 'Run', 'Test', 'Shell', 'Stop', 'Clean', 'All', 'Logs')]
    [string]$Action = 'All',

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'AuditConfig', 'EventGeneration', 'Synthetic', 'Integration')]
    [string]$TestSuite = 'All',

    [Parameter(Mandatory = $false)]
    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'
$ImageName = "win-audit-test"
$ContainerName = "windows-audit-testing"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

# Helper functions
function Write-Header {
    param([string]$Message)
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "  $($Message.PadRight(41)) " -ForegroundColor Cyan
    Write-Host "==========================================`n" -ForegroundColor Cyan
}

function Test-DockerRunning {
    try {
        docker ps | Out-Null
        return $true
    }
    catch {
        Write-Host "Error: Docker is not running or not accessible" -ForegroundColor Red
        Write-Host "Please ensure Docker Desktop is running with Windows containers enabled" -ForegroundColor Yellow
        return $false
    }
}

function Test-ContainerExists {
    $container = docker ps -a --filter "name=$ContainerName" --format "{{.Names}}" 2>$null
    return $container -eq $ContainerName
}

function Test-ContainerRunning {
    $container = docker ps --filter "name=$ContainerName" --format "{{.Names}}" 2>$null
    return $container -eq $ContainerName
}

function Build-DockerImage {
    Write-Header "Building Docker Image"

    Push-Location $ProjectRoot
    
    Write-Host "Building image: $ImageName" -ForegroundColor Yellow
    Write-Host "This may take several minutes on first build..." -ForegroundColor Gray

    docker build -t "${ImageName}:latest" -t "${ImageName}:dev" .

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nSUCCESS: Image built successfully!" -ForegroundColor Green
        docker images $ImageName
    }
    else {
        Write-Host "`nERROR: Image build failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

function Start-Container {
    Write-Header "Starting Container"

    if (Test-ContainerExists) {
        Write-Host "Container '$ContainerName' already exists" -ForegroundColor Yellow
        if (Test-ContainerRunning) {
            Write-Host "Container is already running" -ForegroundColor Green
            return
        }
        else {
            Write-Host "Starting existing container..." -ForegroundColor Yellow
            docker start $ContainerName
            Start-Sleep -Seconds 5
            return
        }
    }

    Write-Host "Creating new container: $ContainerName" -ForegroundColor Yellow

    $runArgs = @(
        'run',
        '-d',
        '--name', $ContainerName,
        '--hostname', 'win-audit-host'
    )

    if ($Interactive) {
        $runArgs += @('-it')
    }

    # Add volume mounts
    $runArgs += @(
        '-v', "${ProjectRoot}\scripts:C:\workspace\scripts",
        '-v', "${ProjectRoot}\test-results:C:\test-results",
        '-v', "${ProjectRoot}\logs:C:\logs"
    )

    $runArgs += "${ImageName}:latest"

    & docker $runArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nWaiting for container to be ready..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10

        # Check health
        $health = docker inspect --format='{{.State.Health.Status}}' $ContainerName 2>$null
        Write-Host "Container health: $health" -ForegroundColor Cyan

        Write-Host "`nSUCCESS: Container started successfully!" -ForegroundColor Green
        docker ps --filter "name=$ContainerName"
    }
    else {
        Write-Host "`nERROR: Failed to start container!" -ForegroundColor Red
        exit 1
    }
}

function Invoke-Tests {
    Write-Header "Running Tests"

    if (-not (Test-ContainerRunning)) {
        Write-Host "Container is not running. Starting container..." -ForegroundColor Yellow
        Start-Container
    }

    Write-Host "Running test suite: $TestSuite" -ForegroundColor Yellow

    docker exec $ContainerName powershell -File C:\workspace\scripts\Run-DockerTests.ps1 `
        -TestSuite $TestSuite `
        -OutputFormat JSON `
        -Verbose

    # Copy results to host
    Write-Host "`nCopying test results to host..." -ForegroundColor Yellow
    if (-not (Test-Path "$ProjectRoot\test-results")) {
        New-Item -ItemType Directory -Path "$ProjectRoot\test-results" | Out-Null
    }

    docker cp "${ContainerName}:C:\test-results\." "$ProjectRoot\test-results\"

    Write-Host "`nSUCCESS: Tests complete! Results saved to: $ProjectRoot\test-results" -ForegroundColor Green
}

function Open-Shell {
    Write-Header "Opening Interactive Shell"

    if (-not (Test-ContainerRunning)) {
        Write-Host "Container is not running. Starting container..." -ForegroundColor Yellow
        Start-Container
    }

    Write-Host "Opening PowerShell in container..." -ForegroundColor Yellow
    Write-Host "Type 'exit' to return to host" -ForegroundColor Gray
    Write-Host ""

    docker exec -it $ContainerName powershell
}

function Show-Logs {
    Write-Header "Container Logs"

    if (-not (Test-ContainerExists)) {
        Write-Host "Container does not exist" -ForegroundColor Red
        return
    }

    docker logs $ContainerName
}

function Stop-Container {
    Write-Header "Stopping Container"

    if (Test-ContainerRunning) {
        Write-Host "Stopping container: $ContainerName" -ForegroundColor Yellow
        docker stop $ContainerName
    }
    else {
        Write-Host "Container is not running" -ForegroundColor Yellow
    }

    if (Test-ContainerExists) {
        Write-Host "Removing container: $ContainerName" -ForegroundColor Yellow
        docker rm $ContainerName
        Write-Host "SUCCESS: Container removed" -ForegroundColor Green
    }
}

function Remove-Everything {
    Write-Header "Cleaning Up"

    # Stop and remove container
    if (Test-ContainerExists) {
        if (Test-ContainerRunning) {
            docker stop $ContainerName
        }
        docker rm $ContainerName
        Write-Host "SUCCESS: Container removed" -ForegroundColor Green
    }

    # Remove image
    $imageExists = docker images -q $ImageName 2>$null
    if ($imageExists) {
        Write-Host "Removing image: $ImageName" -ForegroundColor Yellow
        docker rmi "${ImageName}:latest" "${ImageName}:dev" -f
        Write-Host "SUCCESS: Image removed" -ForegroundColor Green
    }

    # Clean up dangling images
    $dangling = docker images -f "dangling=true" -q 2>$null
    if ($dangling) {
        Write-Host "Cleaning up dangling images..." -ForegroundColor Yellow
        docker rmi $dangling
    }

    Write-Host "`nSUCCESS: Cleanup complete!" -ForegroundColor Green
}

# Main execution
try {
    Write-Header "Windows Audit Docker Testing"

    # Check Docker is available
    if (-not (Test-DockerRunning)) {
        exit 1
    }

    # Execute requested action
    switch ($Action) {
        'Build' {
            Build-DockerImage
        }
        'Run' {
            Start-Container
        }
        'Test' {
            Invoke-Tests
        }
        'Shell' {
            Open-Shell
        }
        'Logs' {
            Show-Logs
        }
        'Stop' {
            Stop-Container
        }
        'Clean' {
            Remove-Everything
        }
        'All' {
            Build-DockerImage
            Start-Container
            Invoke-Tests
        }
    }

    Write-Host ""

}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
