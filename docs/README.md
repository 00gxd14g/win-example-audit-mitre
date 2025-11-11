# Documentation Directory

This directory contains comprehensive documentation for Windows Event IDs, MITRE ATT&CK mappings, and audit configuration guidance.

## Documentation Files

### EVENT_IDS.md
Comprehensive reference for all Windows Security Event IDs that can be logged when using the audit scripts.

**Contents:**
- Event IDs organized by audit category
- Detailed descriptions for each event
- Breakdown by script (SysmonLikeAudit.ps1 vs win-audit.ps1)
- PowerShell logging event references
- Critical security events to monitor
- Event correlation patterns for threat detection
- Logon types and privilege reference
- Analysis tips and query examples

**Use this document to:**
- Understand what events will be generated
- Create SIEM detection rules
- Build correlation queries
- Train security analysts
- Plan log storage requirements

### MITRE_ATTACK_MAPPING.md
Mapping between Windows Security Event IDs and MITRE ATT&CK framework tactics and techniques.

**Contents:**
- Complete mapping table organized by MITRE tactic
- Reverse lookup: Event ID to MITRE technique
- Detection use cases with example queries
- Detailed scenarios for common attack patterns
- Coverage analysis showing gaps
- Recommendations for additional telemetry sources

**Covered MITRE Tactics:**
- TA0001 - Initial Access
- TA0002 - Execution
- TA0003 - Persistence
- TA0004 - Privilege Escalation
- TA0005 - Defense Evasion
- TA0006 - Credential Access
- TA0007 - Discovery
- TA0008 - Lateral Movement
- TA0009 - Collection
- TA0010 - Command and Control
- TA0011 - Exfiltration
- TA0040 - Impact

**Use this document to:**
- Map detections to MITRE ATT&CK
- Identify coverage gaps
- Build threat hunting queries
- Create detection-as-code rules
- Plan security monitoring strategy

## How to Use This Documentation

### For Security Engineers
1. Review `EVENT_IDS.md` to understand available telemetry
2. Use `MITRE_ATTACK_MAPPING.md` to map events to threats
3. Build detection rules based on use cases provided
4. Test detection logic with synthetic logs from `Generate-SyntheticLogs.ps1`

### For Threat Hunters
1. Use `MITRE_ATTACK_MAPPING.md` to identify relevant Event IDs for specific techniques
2. Reference detection use cases for query patterns
3. Correlate multiple events to identify attack chains
4. Use event combinations listed in `EVENT_IDS.md` for threat patterns

### For Incident Responders
1. Reference `EVENT_IDS.md` for event descriptions during investigation
2. Use MITRE mappings to understand attacker TTPs
3. Follow event correlation patterns to reconstruct attack timeline
4. Identify related events for comprehensive forensic analysis

### For Compliance and Audit
1. Use documentation to demonstrate logging coverage
2. Map audit requirements to Event IDs
3. Show alignment with security frameworks (MITRE ATT&CK, NIST)
4. Validate audit policy effectiveness

## Event ID Quick Reference

### Most Critical Event IDs

| Event ID | Description | MITRE Tactics |
|----------|-------------|---------------|
| 4688 | Process Creation | Execution, Discovery, Lateral Movement |
| 4624 | Successful Logon | Initial Access, Lateral Movement |
| 4672 | Special Privileges Assigned | Privilege Escalation |
| 4698 | Scheduled Task Created | Persistence, Execution |
| 4768 | Kerberos TGT Request | Credential Access (Golden Ticket) |
| 4769 | Kerberos Service Ticket | Credential Access (Kerberoasting) |
| 5140 | Network Share Accessed | Lateral Movement, Collection |
| 5156 | Network Connection Allowed | Command & Control, Exfiltration |
| 4657 | Registry Modified | Persistence, Defense Evasion |
| 4104 | PowerShell Script Block | Execution, Defense Evasion |

### Event Log Channels

- **Security**: Most security audit events (4xxx, 5xxx series)
- **System**: System-level events, service installations
- **Microsoft-Windows-PowerShell/Operational**: PowerShell 4103, 4104
- **Windows PowerShell**: PowerShell engine events
- **Microsoft-Windows-TaskScheduler/Operational**: Detailed task events

## Additional Resources

### Official Microsoft Documentation
- [Advanced Security Audit Policy Settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Security Auditing Overview](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)

### MITRE ATT&CK Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Windows](https://attack.mitre.org/matrices/enterprise/windows/)

### Community Resources
- [Ultimate Windows Security Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [NSA Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
- [JPCERT Windows Event Log Analysis](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [SANS Windows Forensics Poster](https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download)

## Updating Documentation

When updating documentation:
1. Maintain consistent formatting and structure
2. Include practical examples and use cases
3. Reference related Event IDs and MITRE techniques
4. Add detection logic when applicable
5. Update version history at bottom of document
6. Cross-reference between documents

## Version History

- **v1.0** (2025-11-11) - Initial comprehensive documentation with MITRE ATT&CK mappings

## Contributing

To contribute to documentation:
1. Verify information against official Microsoft documentation
2. Test queries and detection logic before adding
3. Include sources and references
4. Update cross-references in other documents
5. Add examples for complex concepts
