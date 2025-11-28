# Windows Audit Configuration with Ansible

This directory contains an Ansible playbook to automate the configuration of Windows security auditing, mirroring the functionality of the `SysmonLikeAudit.ps1` PowerShell script.

## Prerequisites

1.  **Ansible Control Node**: A machine with Ansible installed (Linux/WSL/macOS).
2.  **Target Windows Hosts**: Windows machines with WinRM enabled and accessible from the control node.
3.  **Ansible Collections**:
    *   `ansible.windows`
    *   `community.windows` (optional, but good to have)

    Install them using:
    ```bash
    ansible-galaxy collection install ansible.windows
    ```

## Files

*   `site.yml`: The main playbook that applies the configuration.
*   `inventory.yml`: An example inventory file defining target hosts.

## Usage

1.  **Update Inventory**: Edit `inventory.yml` to reflect your actual Windows hosts, IP addresses, and credentials.

    ```yaml
    hosts:
      windows_server_1:
        ansible_host: 192.168.1.50
    vars:
      ansible_user: Administrator
      ansible_password: YourSecurePassword
    ```

2.  **Run the Playbook**:

    ```bash
    ansible-playbook -i inventory.yml site.yml --ask-vault-pass
    ```

## 🔐 Secure Authentication

Storing passwords in cleartext is a security risk. Here are two better ways to authenticate:

### Method 1: Ansible Vault (Recommended)

Encrypt your password so it can be safely stored in the repository.

1.  **Encrypt your password**:
    ```bash
    ansible-vault encrypt_string 'MySecretPassword123!' --name 'vault_password'
    ```

2.  **Update `inventory.yml`**:
    Copy the output block into your inventory file's `vars` section:
    ```yaml
    vars:
      ansible_user: Administrator
      ansible_password: !vault |
        $ANSIBLE_VAULT;1.1;AES256
        34353632626231363130333...
    ```

3.  **Run with Vault Password**:
    ```bash
    ansible-playbook -i inventory.yml site.yml --ask-vault-pass
    ```

### Method 2: OpenSSH for Windows

If your Windows servers have OpenSSH Server installed (available in Windows Server 2019/2022), you can use SSH keys instead of WinRM.

1.  **Configure Inventory**:
    ```yaml
    vars:
      ansible_connection: ssh
      ansible_shell_type: powershell
      ansible_user: Administrator
      # Ensure your public key is in C:\Users\Administrator\.ssh\authorized_keys on the target
    ```

2.  **Run without passwords**:
    ```bash
    ansible-playbook -i inventory.yml site.yml
    ```

## What it Does

The playbook performs the following actions on target hosts:

1.  **Creates Directory**: `C:\pstranscripts` for PowerShell transcription logs.
2.  **Sets Audit Policies**: Enables Success/Failure auditing for critical subcategories (Process Creation, Object Access, etc.).
3.  **Registry Configuration**:
    *   Enables Process Command Line logging (Event ID 4688).
    *   Enables PowerShell Module Logging, Script Block Logging, and Transcription.
4.  **Event Log Configuration**: Sets the maximum size of Security, System, and Application logs to 32MB and enables "Overwrite as needed".

## Verification

After running the playbook, you can verify the configuration on the target Windows host by running the validation script included in this repository:

```powershell
.\scripts\Test-EventIDGeneration.ps1
```
