# Windows Olay Denetimi ve MITRE ATT&CK Wiki

Bu Wiki, Windows güvenlik denetimi, olay günlükleri ve MITRE ATT&CK eşleşmeleri hakkında kapsamlı bilgi kaynağıdır.

## İçindekiler

1. [Giriş](#giriş)
2. [Kurulum ve Yapılandırma](#kurulum-ve-yapılandırma)
3. [Kullanım Kılavuzları](#kullanım-kılavuzları)
4. [Olay Kimliği Referansı](#olay-kimliği-referansı)
5. [MITRE ATT&CK Eşleşmeleri](#mitre-attck-eşleşmeleri)
6. [Docker ile Test](#docker-ile-test)
7. [Sorun Giderme](#sorun-giderme)

---

## Giriş

Bu proje, güvenlik ekiplerinin Windows ortamlarında görünürlüğü artırmasına, tehdit tespit yeteneklerini geliştirmesine ve denetim yapılandırmalarını doğrulamasına yardımcı olmak için tasarlanmıştır.

### Temel Bileşenler

- **Denetim Yapılandırması**: `SysmonLikeAudit.ps1` ve `win-audit.ps1`
- **Test ve Doğrulama**: `Test-EventIDGeneration.ps1`
- **Veri Üretimi**: `Generate-SyntheticLogs.ps1`
- **Konteyner Desteği**: Docker tabanlı test ortamı

---

## Kurulum ve Yapılandırma

### Ön Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici hakları

### Hızlı Kurulum

1. Depoyu klonlayın veya indirin.
2. PowerShell'i Yönetici olarak açın.
3. `scripts` dizinine gidin.
4. `SysmonLikeAudit.ps1` (kapsamlı) veya `win-audit.ps1` (MITRE odaklı) komut dosyasını çalıştırın.

---

## Kullanım Kılavuzları

### Denetim Yapılandırmasını Doğrulama

Yapılandırmanızın doğru uygulandığını ve olayların oluşturulduğunu doğrulamak için:

```powershell
.\scripts\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport
```

### Sentetik Günlük Oluşturma

SIEM veya tespit kurallarınızı test etmek için yapay veriler oluşturun:

```powershell
# Yanal hareket senaryosu
.\scripts\Generate-SyntheticLogs.ps1 -Scenario LateralMovement

# Tüm senaryolar
.\scripts\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity
```

---

## Olay Kimliği Referansı

Kritik Windows Güvenlik Olayları:

- **4688**: İşlem Oluşturma (Komut satırı argümanları ile)
- **4624/4625**: Oturum Açma Başarılı/Başarısız
- **4698**: Zamanlanmış Görev Oluşturma
- **4768/4769**: Kerberos İşlemleri
- **4104**: PowerShell Komut Bloğu Günlüğü
- **5156**: Windows Filtreleme Platformu Bağlantısı

Daha fazla detay için [EVENT_IDS.md](../docs/EVENT_IDS.md) dosyasına bakın.

---

## MITRE ATT&CK Eşleşmeleri

Proje, Windows olaylarını aşağıdaki MITRE taktikleriyle eşleştirir:

- **Initial Access (İlk Erişim)**: T1078 (Geçerli Hesaplar)
- **Execution (Yürütme)**: T1059 (Komut ve Komut Dosyası Yorumlayıcısı)
- **Persistence (Kalıcılık)**: T1053 (Zamanlanmış Görev/İş)
- **Privilege Escalation (Ayrıcalık Yükseltme)**: T1078 (Geçerli Hesaplar)
- **Defense Evasion (Savunma Atlatma)**: T1070 (Gösterge Kaldırma)
- **Credential Access (Kimlik Bilgisi Erişimi)**: T1003 (OS Kimlik Bilgisi Dökümü)
- **Discovery (Keşif)**: T1087 (Hesap Keşfi)
- **Lateral Movement (Yanal Hareket)**: T1021 (Uzak Hizmetler)

---

## Docker ile Test

Güvenli ve izole bir ortamda test yapmak için Docker desteği sunulmaktadır.

### Başlarken

```powershell
.\scripts\Local-DockerTest.ps1 -Action All
```

Bu komut:
1. Docker imajını oluşturur.
2. Konteyneri başlatır.
3. Tüm test paketlerini çalıştırır.
4. Sonuçları `test-results` klasörüne kopyalar.

---

## Sorun Giderme

### Olaylar Oluşmuyor

- **Grup İlkesi**: Yerel ayarların GPO tarafından ezilmediğinden emin olun (`gpresult /r`).
- **Hizmet Durumu**: `EventLog` hizmetinin çalıştığını kontrol edin.
- **Denetim Durumu**: `auditpol /get /category:*` ile mevcut durumu kontrol edin.

### Performans Sorunları

- Dosya Sistemi denetimini devre dışı bırakın veya sınırlayın.
- İşlem oluşturma için yalnızca "Başarı" denetimini kullanın.
- Olay günlüğü boyutlarını artırın (`wevtutil sl Security /ms:67108864`).
