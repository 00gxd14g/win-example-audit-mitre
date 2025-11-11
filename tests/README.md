# Tests Directory

This directory is reserved for future automated testing scripts and validation tools.

## Purpose

This directory will contain:
- Automated test suites for audit configuration
- Validation scripts for event generation
- Integration tests for SIEM forwarding
- Compliance verification tests
- Performance impact testing

## Planned Test Suites

### Configuration Tests
- Validate audit policies are correctly applied
- Verify registry settings for PowerShell logging
- Check event log sizes and retention settings
- Test Group Policy precedence

### Event Generation Tests
- Verify specific Event IDs are being generated
- Test event content and field population
- Validate PowerShell logging captures scripts
- Confirm command-line logging in process creation

### Integration Tests
- Test event forwarding to SIEM
- Validate log shipping mechanisms
- Check event retention and rotation
- Test performance impact on system

### Compliance Tests
- Verify alignment with security frameworks (CIS, NIST, PCI-DSS)
- Check coverage of required audit categories
- Validate log retention policies
- Test access controls on log files

## Testing Tools

Future testing will leverage:
- **Pester**: PowerShell testing framework
- **Invoke-AtomicRedTest**: MITRE ATT&CK test framework
- **Caldera**: Automated adversary emulation
- **Custom test harnesses** for specific scenarios

## Usage

Tests will be runnable via:
```powershell
# Run all tests
.\Run-AllTests.ps1

# Run specific test suite
.\Run-ConfigurationTests.ps1

# Run with detailed output
.\Run-AllTests.ps1 -Verbose -DetailedReport
```

## Contributing Tests

When adding tests:
1. Use Pester framework for consistency
2. Include both positive and negative test cases
3. Mock external dependencies when possible
4. Provide clear test descriptions
5. Include setup and teardown logic
6. Document expected outcomes

Example test structure:
```powershell
Describe "Audit Policy Configuration Tests" {
    Context "Process Creation Auditing" {
        It "Should have Process Creation audit enabled" {
            $result = auditpol /get /subcategory:"Process Creation"
            $result | Should -Match "Success"
        }

        It "Should include command line in process events" {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
            $regValue.ProcessCreationIncludeCmdLine_Enabled | Should -Be 1
        }
    }
}
```

## Related Tools

- [../scripts/Test-EventIDGeneration.ps1](../scripts/Test-EventIDGeneration.ps1) - Current testing script
- [../scripts/Generate-SyntheticLogs.ps1](../scripts/Generate-SyntheticLogs.ps1) - Synthetic log generation for testing

## Future Enhancements

1. **Automated CI/CD Integration**: Run tests on code changes
2. **Performance Benchmarking**: Measure system impact
3. **Coverage Reports**: Track audit policy coverage
4. **Regression Testing**: Ensure updates don't break existing functionality
5. **Multi-Environment Testing**: Test across different Windows versions
