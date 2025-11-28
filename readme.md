# Windows Event Auditing & MITRE ATT&CK Mapping

[![Build Status](https://github.com/00gxd14g/win-example-audit-mitre/actions/workflows/windows-docker-tests.yml/badge.svg)](https://github.com/00gxd14g/win-example-audit-mitre/actions/workflows/windows-docker-tests.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://microsoft.com/powershell)
[![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)](https://www.microsoft.com/windows)

**[🇹🇷 Türkçe README için tıklayın](README.tr.md)** | **[📚 Wiki Documentation](docs/WIKI.md)**

This repository provides a complete toolkit for configuring, testing, and validating Windows Security Auditing. It bridges the gap between theoretical detection logic (MITRE ATT&CK) and practical implementation (Windows Event Logs).

## 🚀 Key Features

*   **🛡️ Audit Configuration**: Ready-to-use PowerShell scripts to enable comprehensive logging (Sysmon-like or MITRE-focused).
*   **🎯 MITRE ATT&CK Mapping**: Detailed mapping of Windows Event IDs to specific attack techniques.
*   **🧪 Validation Tools**: Scripts to verify that your audit policies are actually generating the expected logs.
*   **🤖 Synthetic Data**: Generate realistic attack scenarios (Lateral Movement, Credential Dumping) to test your SIEM.
*   **🐳 Docker Testing**: Isolated, reproducible testing environment using Windows containers.
*   **📜 Ansible Support**: Automate deployment across your fleet with the included Ansible playbook.

## 📂 Repository Structure

```text
win-example-audit-mitre/
├── scripts/
│   ├── SysmonLikeAudit.ps1        # Advanced audit policy configuration
│   ├── win-audit.ps1              # MITRE-guided audit policy
│   ├── Test-EventIDGeneration.ps1 # Validation and testing tool
│   ├── Generate-SyntheticLogs.ps1 # Synthetic log generator
│   └── Local-DockerTest.ps1       # Docker helper script
├── ansible/                       # Ansible automation
│   ├── site.yml                   # Main playbook
│   └── inventory.yml              # Example inventory
├── docs/
│   ├── EVENT_IDS.md               # Event ID reference
│   ├── MITRE_ATTACK_MAPPING.md    # Attack technique mappings
│   └── WIKI.md                    # Comprehensive guide
└── .github/workflows/             # CI/CD automation
```

## 🏁 Quick Start

### 1. Configure Auditing
Run PowerShell as **Administrator** and choose your configuration:

```powershell
# Option A: Comprehensive (Recommended) - Enables detailed logging including Process Creation args
.\scripts\SysmonLikeAudit.ps1

# Option B: MITRE Focused - Optimized for specific technique detection
.\scripts\win-audit.ps1
```

### 2. Verify Configuration
Ensure your policies are active and events are being generated:

```powershell
.\scripts\Test-EventIDGeneration.ps1 -TestEventGeneration
```

**Expected Output:**
```text
╔════════════════════════════════════════════╗
║  Windows Audit Configuration Check         ║
╚════════════════════════════════════════════╝

[PASS] Administrator Privileges
[PASS] Event Log Service Status
[PASS] Audit Policy: Process Creation
[PASS] Audit Policy: Object Access
[PASS] Registry: Process Command Line Logging
[PASS] Registry: PowerShell Script Block Logging

✓ Configuration verified successfully.
```

### 3. Generate Test Data
Test your detection rules by simulating attack traffic:

```powershell
.\scripts\Generate-SyntheticLogs.ps1 -Scenario LateralMovement
```

**Expected Output:**
```text
========================================
Synthetic Windows Event Log Generator
========================================
[*] Scenario: LateralMovement
[+] Generating Event 4624 (Logon Type 3 - Network)...
[+] Generating Event 5140 (Share Access)...
[+] Generating Event 4648 (Explicit Credential Logon)...

Successfully generated 15 events to .\SyntheticLogs
```

## 🐳 Docker Testing

Don't want to mess with your host machine? Use our Docker environment!

```powershell
# Build image, start container, and run all tests
.\scripts\Local-DockerTest.ps1 -Action All
```

This will spin up a Windows Server Core container, apply the audit policies, run the validation suite, and give you a report—all without touching your local registry.

## 📜 Ansible Automation

Scale your security configuration across your entire fleet using our Ansible playbook.

```bash
# 1. Update inventory
nano ansible/inventory.yml

# 2. Run playbook
ansible-playbook -i ansible/inventory.yml ansible/site.yml --ask-vault-pass
```

This playbook replicates the comprehensive `SysmonLikeAudit` configuration, ensuring consistent security posture across all your Windows servers. See [ansible/README.md](ansible/README.md) for details.

## 📚 Documentation

*   **[Wiki](docs/WIKI.md)**: The central hub for all documentation.
*   **[Event ID Reference](docs/EVENT_IDS.md)**: What does Event 4688 mean? Find out here.
*   **[MITRE Mapping](docs/MITRE_ATTACK_MAPPING.md)**: Which events detect "Credential Dumping"?

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) (coming soon) or simply fork and submit a PR.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
