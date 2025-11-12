<#
.SYNOPSIS
    Configures Windows audit policies and logging settings based on MITRE ATT&CK guidance.

.DESCRIPTION
    This script enables Windows audit logs guided by MITRE ATT&CK, configures log size and retention
    settings, and enables advanced PowerShell logging. It is designed to minimize false positive
    (FP) logging by limiting some categories to success-only or disabling failure logging where
    it is typically noisy.

    The script performs the following main actions:
    1. Sets various audit policy subcategories using `auditpol`.
    2. Configures process creation to include command-line arguments.
    3. Enables PowerShell Module Logging, Script Block Logging, and Transcription.
    4. Sets the size of the Security, System, and Application logs to 32 MB and configures them
       to overwrite old events as needed.

    The original comments in this script are in Turkish.

.EXAMPLE
    PS C:\> .\win-audit.ps1
    Executes the script to apply the audit and logging configurations. This command must be run
    from an elevated PowerShell prompt (Run as Administrator).

.NOTES
    - This script must be run with Administrator privileges.
    - The execution policy for PowerShell scripts must be set to allow running local scripts.
      You can set this for the current process by running:
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#>

# Requires -ExecutionPolicy Bypass
# Bu script, Windows üzerinde audit (denetim) loglarını MITRE ATT&CK rehberliğinde etkinleştirir,
# log boyutu / saklama ayarlarını düzenler, Powershell gelişmiş loglarını açar
# ve gereksiz (FP) loglamayı en aza indirmek için bazı kategorileri yalnızca başarı/açık kapalı şeklinde sınırlar.
# Lütfen betiği Yönetici (Administrator) olarak çalıştırın.

# Import logging module
$loggingModule = Join-Path -Path $PSScriptRoot -ChildPath "Write-AuditLog.ps1"
if (Test-Path $loggingModule) {
    . $loggingModule
    Initialize-AuditLogging -ScriptName "win-audit" -EnableTranscript
    Write-AuditLog -Message "Script started - Configuring Windows Audit Policies" -Level Info
} else {
    Write-Warning "Logging module not found at $loggingModule - continuing without enhanced logging"
}

# Force UTF-8 output to avoid mojibake (e.g., Turkish characters)
try { chcp 65001 > $null } catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "`n=== Windows Audit Policy ve Log Ayarlarını Yapılandırma Başlıyor... ===`n"

# 1) Audit Policileri Ayarlama (auditpol komutları)
# --------------------------------------------------

Write-Host "Audit Policy alt kategorileri etkinleştiriliyor..."
if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
    Write-AuditLog -Message "Configuring audit policy subcategories" -Level Info
}

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
    Write-AuditLog -Message "Enabled Logon auditing (success and failure)" -Level Debug
}

auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
    Write-AuditLog -Message "Enabled Directory Service Changes auditing" -Level Debug
}

auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
    Write-AuditLog -Message "Enabled Process Creation auditing (success only)" -Level Debug
}
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:disable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:disable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable

Write-Host "Audit Policileri güncellendi.`n"

# 2) Process Creation ve PowerShell Log Ayarları
# ----------------------------------------------
Write-Host "Process Creation (komut satırı) ve PowerShell log ayarları yapılıyor..."

# Process Creation komut satırını eklemek için:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    /v "*" /t REG_SZ /d "*" /f

# PowerShell Script Block Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# PowerShell Transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    /v OutputDirectory /t REG_SZ /d "C:\pstranscripts" /f

Write-Host "Process Creation ve PowerShell log ayarları tamamlandı.`n"

# 3) Windows Event Log Boyutu ve Saklama (Retention) Ayarları
# -----------------------------------------------------------
# Aşağıdaki örnek Security, System ve Application loglarını 32 MB (33554432 byte) ile sınırlar,
# Retention = 0 ise 'Overwrite as needed' anlamına gelir.

Write-Host "Event Log boyutu ve saklama ayarları yapılandırılıyor..."

$maxLogSize = 33554432  # 32 MB (Byte cinsinden)
$logPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security",
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System",
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
)

foreach ($logPath in $logPaths) {
    # Log boyutu
    Set-ItemProperty -Path $logPath -Name "MaxSize" -Value $maxLogSize
    # Retention=0 => Overwrite As Needed
    Set-ItemProperty -Path $logPath -Name "Retention" -Value 0
}

Write-Host "Event Log boyutu ve saklama ayarları tamamlandı.`n"

if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
    Write-AuditLog -Message "Event log size and retention settings completed" -Level Success
    Write-AuditLog -Message "All Windows audit policies have been successfully applied" -Level Success
}

Write-Host "=== Tüm ayarlar başarıyla uygulandı! ==="
Write-Output "İşlem tamamlandı."

# Stop logging if module is available
if (Get-Command Stop-AuditLogging -ErrorAction SilentlyContinue) {
    Stop-AuditLogging -ScriptName "win-audit"
}
