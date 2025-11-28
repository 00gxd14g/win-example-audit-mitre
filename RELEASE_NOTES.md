# Sürüm Notları - v2.1.0

## Yenilikler

Bu sürüm, algoritmik güncellemeler ve genişletilmiş MITRE ATT&CK kapsamı ile denetim ve test yeteneklerini güçlendirmektedir.

### 🚀 Yeni Özellikler

- **Gelişmiş Denetim Kapsamı**:
  - `Process Termination` (Olay 4689) denetimi eklendi.
  - `System Integrity` ve `RPC Events` denetimi eklendi.
- **MITRE ATT&CK Eşleşmeleri**:
  - T1070.006 (Timestomp) eklendi.
  - T1569.002 (Service Execution) eklendi.
  - T1003.001 (LSASS Memory) için AccessMask detayları eklendi.
- **Test Güncellemeleri**:
  - `Test-EventIDGeneration.ps1` artık İşlem Sonlandırma ve Kayıt Defteri değişikliklerini daha kapsamlı test ediyor.
  - `Local-DockerTest.ps1` sözdizimi hataları giderildi ve kararlılığı artırıldı.

### 🐛 Düzeltmeler

- `Local-DockerTest.ps1` içindeki kritik sözdizimi hataları (try/catch blokları) düzeltildi.
- `Test-EventIDGeneration.ps1` içindeki test mantığı iyileştirildi.

## Kurulum ve Kullanım

1. Depoyu güncelleyin.
2. `SysmonLikeAudit.ps1` komut dosyasını yeniden çalıştırarak yeni denetim ilkelerini uygulayın.
3. `Test-EventIDGeneration.ps1 -TestEventGeneration` ile yeni olayların (4689 vb.) oluştuğunu doğrulayın.
