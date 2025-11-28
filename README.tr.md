# Windows Olay Denetimi ve MITRE ATT&CK Eşleştirmesi

[![Build Status](https://github.com/00gxd14g/win-example-audit-mitre/actions/workflows/windows-docker-tests.yml/badge.svg)](https://github.com/00gxd14g/win-example-audit-mitre/actions/workflows/windows-docker-tests.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://microsoft.com/powershell)
[![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)](https://www.microsoft.com/windows)

**[🇺🇸 English README](readme.md)** | **[📚 Wiki Dokümantasyonu](docs/WIKI.md)**

Bu proje, Windows Güvenlik Denetimi'ni yapılandırmak, test etmek ve doğrulamak için kapsamlı bir araç seti sunar. Teorik tespit mantığı (MITRE ATT&CK) ile pratik uygulama (Windows Olay Günlükleri) arasındaki boşluğu doldurmayı amaçlar.

## 🚀 Temel Özellikler

*   **🛡️ Denetim Yapılandırması**: Kapsamlı loglamayı (Sysmon benzeri veya MITRE odaklı) etkinleştirmek için hazır PowerShell betikleri.
*   **🎯 MITRE ATT&CK Eşleştirmesi**: Windows Olay Kimliklerinin (Event IDs) belirli saldırı teknikleriyle detaylı eşleştirmesi.
*   **🧪 Doğrulama Araçları**: Denetim politikalarınızın gerçekten beklenen logları üretip üretmediğini doğrulayan test betikleri.
*   **🤖 Sentetik Veri**: SIEM sisteminizi test etmek için gerçekçi saldırı senaryoları (Yanal Hareket, Kimlik Bilgisi Çalma vb.) üretimi.
*   **🐳 Docker Testi**: Windows konteynerleri kullanarak izole edilmiş, tekrarlanabilir test ortamı.
*   **📜 Ansible Desteği**: Dahil edilen Ansible playbook ile dağıtımı tüm filonuzda otomatikleştirin.

## 📂 Proje Yapısı

```text
win-example-audit-mitre/
├── scripts/
│   ├── SysmonLikeAudit.ps1        # Gelişmiş denetim politikası yapılandırması
│   ├── win-audit.ps1              # MITRE rehberliğinde denetim politikası
│   ├── Test-EventIDGeneration.ps1 # Doğrulama ve test aracı
│   ├── Generate-SyntheticLogs.ps1 # Sentetik log üreticisi
│   └── Local-DockerTest.ps1       # Docker yardımcı betiği
├── ansible/                       # Ansible otomasyonu
│   ├── site.yml                   # Ana playbook
│   └── inventory.yml              # Örnek envanter
├── docs/
│   ├── EVENT_IDS.md               # Olay Kimliği referansı
│   ├── MITRE_ATTACK_MAPPING.md    # Saldırı tekniği eşleştirmeleri
│   └── WIKI.md                    # Kapsamlı kullanım kılavuzu
└── .github/workflows/             # CI/CD otomasyonu
```

## 🏁 Hızlı Başlangıç

### 1. Denetimi Yapılandırın
PowerShell'i **Yönetici Olarak** çalıştırın ve ihtiyacınıza uygun yapılandırmayı seçin:

```powershell
# Seçenek A: Kapsamlı (Önerilen) - İşlem oluşturma argümanları dahil detaylı loglama
.\scripts\SysmonLikeAudit.ps1

# Seçenek B: MITRE Odaklı - Belirli teknikleri tespite yönelik optimize edilmiş
.\scripts\win-audit.ps1
```

### 2. Yapılandırmayı Doğrulayın
Politikalarınızın aktif olduğunu ve olayların üretildiğini kontrol edin:

```powershell
.\scripts\Test-EventIDGeneration.ps1 -TestEventGeneration
```

**Beklenen Çıktı:**
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

### 3. Test Verisi Üretin
Saldırı trafiğini simüle ederek tespit kurallarınızı test edin:

```powershell
.\scripts\Generate-SyntheticLogs.ps1 -Scenario LateralMovement
```

**Beklenen Çıktı:**
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

## 🐳 Docker ile Test

Ana makinenizin ayarlarını değiştirmek istemiyor musunuz? Docker ortamımızı kullanın!

```powershell
# İmajı oluştur, konteyneri başlat ve tüm testleri çalıştır
.\scripts\Local-DockerTest.ps1 -Action All
```

Bu komut, bir Windows Server Core konteyneri ayağa kaldırır, denetim politikalarını uygular, doğrulama testlerini çalıştırır ve size bir rapor sunar; üstelik yerel kayıt defterinize (registry) dokunmadan.

## 📚 Dokümantasyon

*   **[Wiki](docs/WIKI.md)**: Tüm dokümantasyonun merkezi.
*   **[Olay Kimliği Referansı](docs/EVENT_IDS.md)**: Olay 4688 ne anlama gelir? Buradan öğrenin.
*   **[MITRE Eşleştirmesi](docs/MITRE_ATTACK_MAPPING.md)**: Hangi olaylar "Credential Dumping" saldırısını tespit eder?

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen projeyi fork'layın ve bir PR (Pull Request) gönderin.

1.  Projeyi Fork'layın
2.  Özellik Dalınızı Oluşturun (`git checkout -b feature/HarikaOzellik`)
3.  Değişikliklerinizi Commit Edin (`git commit -m 'HarikaOzellik eklendi'`)
4.  Dalınıza Push Edin (`git push origin feature/HarikaOzellik`)
5.  Bir Pull Request Açın

## 📄 Lisans

Bu proje MIT Lisansı altında dağıtılmaktadır. Daha fazla bilgi için `LICENSE` dosyasına bakın.
