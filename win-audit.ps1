# Requires -ExecutionPolicy Bypass
# Bu script, Windows üzerinde audit (denetim) loglarını MITRE ATT&CK rehberliğinde etkinleştirir,
# log boyutu / saklama ayarlarını düzenler, Powershell gelişmiş loglarını açar
# ve gereksiz (FP) loglamayı en aza indirmek için bazı kategorileri yalnızca başarı/açık kapalı şeklinde sınırlar.
# Lütfen betiği Yönetici (Administrator) olarak çalıştırın.

Write-Host "`n=== Windows Audit Policy ve Log Ayarlarını Yapılandırma Başlıyor... ===`n"

# 1) Audit Policileri Ayarlama (auditpol komutları)
# --------------------------------------------------

Write-Host "Audit Policy alt kategorileri etkinleştiriliyor..."

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
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
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" ^
    /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" ^
    /v "*" /t REG_SZ /d "*" /f

# PowerShell Script Block Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" ^
    /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# PowerShell Transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" ^
    /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" ^
    /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" ^
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

Write-Host "=== Tüm ayarlar başarıyla uygulandı! ==="
Write-Output "İşlem tamamlandı."
