# CI/CD Integration Guide

This document describes the continuous integration and continuous deployment (CI/CD) setup for automated testing of Windows Event Log auditing configurations.

## Table of Contents

- [Overview](#overview)
- [GitHub Actions Workflows](#github-actions-workflows)
- [Workflow Architecture](#workflow-architecture)
- [Test Execution](#test-execution)
- [Results and Reporting](#results-and-reporting)
- [Custom Workflows](#custom-workflows)
- [Self-Hosted Runners](#self-hosted-runners)
- [Best Practices](#best-practices)

## Overview

The project uses GitHub Actions for CI/CD automation with the following capabilities:

- **Automated Testing**: Runs on every push and pull request
- **Windows Docker Containers**: Tests run in isolated Windows containers
- **Parallel Execution**: Multiple test suites run concurrently
- **Comprehensive Reporting**: Detailed test results and summaries
- **PR Integration**: Automatic comments on pull requests with test results

## GitHub Actions Workflows

### 1. Full Test Suite (`windows-docker-tests.yml`)

**Purpose**: Comprehensive testing of all audit configurations and event generation

**Triggers**:
```yaml
on:
  push:
    branches: [main, develop, 'claude/**']
  pull_request:
    branches: [main, develop]
  workflow_dispatch:
```

**Jobs**:
1. **Build** (5-10 minutes)
   - Builds Windows Docker image
   - Creates image artifact for other jobs
   - Validates Dockerfile syntax

2. **Test-Audit-Config** (5-10 minutes)
   - Validates audit policy configuration
   - Checks registry settings
   - Verifies PowerShell logging setup

3. **Test-Event-Generation** (10-15 minutes)
   - Tests actual event creation
   - Validates Event Log entries
   - Verifies event IDs are logged correctly

4. **Test-Synthetic-Logs** (10-15 minutes)
   - Generates synthetic attack scenarios
   - Creates realistic security events
   - Tests multiple MITRE ATT&CK techniques

5. **Test-Integration** (15-20 minutes)
   - End-to-end testing
   - Full audit pipeline validation
   - Cross-component integration tests

6. **Report** (2-5 minutes)
   - Aggregates all test results
   - Generates markdown report
   - Posts summary to PR (if applicable)

**Total Runtime**: ~30-40 minutes (with parallelization)

### 2. Quick PR Test (`pr-quick-test.yml`)

**Purpose**: Fast validation for pull requests

**Triggers**:
```yaml
on:
  pull_request:
    branches: [main, develop]
```

**Checks** (3-5 minutes total):
- PowerShell syntax validation
- Dockerfile syntax check
- Documentation presence
- Script help documentation
- Quick smoke tests (non-Docker)

## Workflow Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GitHub Actions                     │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌─────────┐                                         │
│  │  Build  │ ──> Image Artifact                     │
│  └─────────┘                                         │
│       │                                               │
│       ├──┬──┬──┬──> Parallel Test Jobs               │
│       │  │  │  │                                      │
│  ┌────▼──▼──▼──▼─────┐                              │
│  │ Test Jobs (4x)     │                              │
│  │ - Audit Config     │                              │
│  │ - Event Gen        │                              │
│  │ - Synthetic        │                              │
│  │ - Integration      │                              │
│  └────────┬───────────┘                              │
│           │                                           │
│      ┌────▼─────┐                                    │
│      │  Report  │ ──> Summary + PR Comment           │
│      └──────────┘                                    │
│                                                       │
└─────────────────────────────────────────────────────┘
```

## Test Execution

### Automatic Triggers

**On Push**:
```bash
# Push to main branch triggers full test suite
git push origin main

# Push to feature branch with 'claude/' prefix triggers tests
git push origin claude/new-feature
```

**On Pull Request**:
```bash
# Opening a PR triggers both workflows:
# 1. Quick PR test (fast validation)
# 2. Full test suite (comprehensive testing)
```

### Manual Triggers

```yaml
# workflow_dispatch allows manual execution
```

**Via GitHub UI**:
1. Go to Actions tab
2. Select "Windows Docker Audit Testing"
3. Click "Run workflow"
4. Choose branch and test suite
5. Click "Run workflow" button

**Via GitHub CLI**:
```bash
# Run all tests on current branch
gh workflow run windows-docker-tests.yml

# Run specific test suite
gh workflow run windows-docker-tests.yml -f test_suite=EventGeneration
```

### Test Suite Selection

When manually triggering, you can choose:
- `All`: Complete test suite
- `AuditConfig`: Configuration validation only
- `EventGeneration`: Event creation tests
- `Synthetic`: Synthetic log generation
- `Integration`: End-to-end tests

## Results and Reporting

### Viewing Results

**GitHub Actions UI**:
1. Navigate to repository
2. Click "Actions" tab
3. Select workflow run
4. View job results and logs

**Job Logs**:
- Each job shows detailed execution logs
- Test output with PASS/FAIL indicators
- Error messages and stack traces
- Container logs for debugging

### Test Artifacts

Each workflow run produces artifacts:

**1. Test Results**
```
audit-config-test-results/
  test-results-20250112-143022.json

event-generation-test-results/
  test-results-20250112-143145.json

synthetic-logs-test-results/
  test-results-20250112-143308.json
  synthetic-CredentialDumping/
  synthetic-LateralMovement/

integration-test-results/
  test-results-20250112-143521.json
```

**2. Test Summary**
```
test-summary/
  test-summary.json
  TEST_REPORT.md
```

**Downloading Artifacts**:
```bash
# Using GitHub CLI
gh run download <run-id>

# Or via UI
Actions > Workflow Run > Artifacts section > Download
```

### PR Comments

For pull requests, the workflow automatically posts a comment with:

```markdown
# Windows Audit Testing Report

**Workflow:** Windows Docker Audit Testing
**Run:** #123
**Commit:** abc1234
**Branch:** feature/new-audit-policy

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | 45 |
| Passed | 43 |
| Failed | 2 |
| Success Rate | 95.56% |

## Test Results by Suite
[Detailed results for each test suite]
```

### Interpreting Results

**Success Criteria**:
- All test jobs complete successfully
- No failed tests in any suite
- Container health checks pass
- Event generation verified

**Common Failures**:
- **Audit policy not applied**: Check container permissions
- **Event not found**: Event Log might need more time
- **Registry setting missing**: Dockerfile configuration issue
- **Container timeout**: Increase timeout or reduce test scope

## Custom Workflows

### Creating Custom Workflows

```yaml
# .github/workflows/custom-test.yml
name: Custom Audit Test

on:
  workflow_dispatch:
    inputs:
      scenario:
        description: 'Attack scenario to test'
        required: true
        type: choice
        options:
          - CredentialDumping
          - LateralMovement
          - PrivilegeEscalation

jobs:
  custom-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build container
        run: docker build -t test .

      - name: Run custom test
        run: |
          docker run --name test-container test
          docker exec test-container powershell `
            -File C:\workspace\scripts\Generate-SyntheticLogs.ps1 `
            -Scenario ${{ github.event.inputs.scenario }}
```

### Scheduled Testing

```yaml
# Run tests daily at 2 AM UTC
on:
  schedule:
    - cron: '0 2 * * *'
```

### Multi-Environment Testing

```yaml
strategy:
  matrix:
    os: [windows-2019, windows-2022]
    test-suite: [AuditConfig, EventGeneration]
```

## Self-Hosted Runners

For organizations requiring self-hosted runners:

### Setup

1. **Register Runner**:
   ```bash
   # Download and configure runner
   mkdir actions-runner && cd actions-runner
   # Follow GitHub's runner setup instructions
   ```

2. **Configure for Windows Containers**:
   ```bash
   # Ensure Docker Desktop is installed
   # Switch to Windows containers
   & $Env:ProgramFiles\Docker\Docker\DockerCli.exe -SwitchWindowsEngine

   # Configure runner as service
   .\svc.sh install
   .\svc.sh start
   ```

3. **Update Workflow**:
   ```yaml
   jobs:
     test:
       runs-on: [self-hosted, windows, docker]
   ```

### Benefits

- **Faster execution**: No queue time
- **Custom configuration**: Tailored to your needs
- **Access to internal resources**: Can test with internal SIEM
- **Cost control**: No GitHub Actions minutes consumed

### Requirements

- Windows Server 2016+ or Windows 10/11
- Docker Desktop with Windows containers
- 16GB RAM minimum
- 100GB free disk space
- Stable network connection

## Best Practices

### 1. Fail Fast

```yaml
jobs:
  quick-validate:
    runs-on: windows-latest
    steps:
      - name: Syntax check
        run: # Quick syntax validation

  full-test:
    needs: quick-validate
    # Only run if validation passes
```

### 2. Timeout Configuration

```yaml
jobs:
  test:
    timeout-minutes: 30  # Prevent hung jobs
    steps:
      - name: Run tests
        timeout-minutes: 20  # Step-level timeout
```

### 3. Conditional Execution

```yaml
jobs:
  test:
    if: github.event_name == 'pull_request' || contains(github.ref, 'main')
```

### 4. Matrix Testing

```yaml
strategy:
  matrix:
    test-suite: [AuditConfig, EventGeneration, Synthetic]
  fail-fast: false  # Continue even if one fails
```

### 5. Caching

```yaml
- name: Cache Docker layers
  uses: actions/cache@v3
  with:
    path: C:\ProgramData\Docker
    key: docker-${{ hashFiles('Dockerfile') }}
```

### 6. Secrets Management

```yaml
env:
  SIEM_API_KEY: ${{ secrets.SIEM_API_KEY }}
```

### 7. Notification Integration

```yaml
- name: Notify on failure
  if: failure()
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        body: '❌ Tests failed! Please check logs.'
      })
```

## Troubleshooting

### Common CI Issues

**1. Container Build Fails**
```yaml
- name: Debug build
  if: failure()
  run: |
    docker images
    docker ps -a
    Get-Content Dockerfile
```

**2. Tests Timeout**
```yaml
# Increase timeout
timeout-minutes: 45
```

**3. Artifact Upload Fails**
```yaml
- name: Upload results
  if: always()  # Upload even on failure
  continue-on-error: true
```

**4. Runner Out of Space**
```yaml
- name: Clean up Docker
  run: |
    docker system prune -af
    docker volume prune -f
```

## Monitoring and Metrics

### Key Metrics to Track

1. **Test Success Rate**: Percentage of passing tests
2. **Execution Time**: Total workflow duration
3. **Failure Rate**: Failed workflows per branch
4. **Coverage**: Number of Event IDs tested

### Creating Dashboards

Use GitHub API to collect metrics:

```powershell
# Get workflow runs
$runs = gh api repos/:owner/:repo/actions/workflows/windows-docker-tests.yml/runs

# Analyze results
$runs | ConvertFrom-Json | Select-Object -ExpandProperty workflow_runs |
  Select-Object id, conclusion, created_at, updated_at
```

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Windows Container CI/CD](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment)
- [Docker CI Best Practices](https://docs.docker.com/build/ci/)
- [GitHub Actions Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)

## Support

For CI/CD issues:
1. Check workflow logs in GitHub Actions UI
2. Review job annotations and warnings
3. Download and analyze test artifacts
4. Open issue with workflow run ID and logs
