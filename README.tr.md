# Windows Olay Denetimi ve MITRE ATT&CK Eşleşmesi

Bu depo, kapsamlı Windows güvenlik denetimi komut dosyaları, test araçları ve MITRE ATT&CK çerçevesi eşleşmeleri sağlar. Kuruluşların güçlü güvenlik günlük kaydı yapılandırmasına, test olayı oluşturmasına ve etkili tehdit tespiti için Windows Olay Kimliklerini saldırı teknikleriyle eşleştirmesine olanak tanır.

## Özellikler

- **Denetim Yapılandırma Komut Dosyaları**: Kapsamlı Windows güvenlik günlük kaydını etkinleştirmek için iki PowerShell komut dosyası
- **MITRE ATT&CK Eşleşmesi**: Windows Olay Kimliklerinin MITRE ATT&CK taktikleri ve teknikleriyle tam eşleşmesi
- **Test Araçları**: Denetim yapılandırmasını ve olay oluşturmayı doğrulamak için komut dosyaları
- **Sentetik Günlük Oluşturma**: SIEM testi ve tespit kuralı doğrulaması için gerçekçi test günlükleri oluşturma
- **Docker Konteyner Testi**: Tekrarlanabilir, güvenli testler için izole edilmiş Windows konteynerleri
- **CI/CD Entegrasyonu**: Otomatik testler için GitHub Actions iş akışları
- **Kapsamlı Dokümantasyon**: Ayrıntılı Olay Kimliği referansı ve tespit kullanım durumları

## Depo Yapısı

```
win-example-audit-mitre/
├── scripts/              # Denetim yapılandırması, test ve günlük oluşturma için PowerShell komut dosyaları
│   ├── SysmonLikeAudit.ps1              # Kapsamlı denetim yapılandırması
│   ├── win-audit.ps1                    # MITRE ATT&CK rehberliğinde denetim yapılandırması
│   ├── Test-EventIDGeneration.ps1       # Olay oluşturmayı test et ve doğrula
│   ├── Generate-SyntheticLogs.ps1       # Test için sentetik günlükler oluştur
│   ├── Run-DockerTests.ps1              # Docker test çalıştırıcısı
│   └── Local-DockerTest.ps1             # Yerel Docker test yardımcısı
├── docs/                 # Olay Kimlikleri ve MITRE eşleşmeleri için dokümantasyon
│   ├── EVENT_IDS.md                     # Kapsamlı Olay Kimliği referansı
│   ├── MITRE_ATTACK_MAPPING.md          # MITRE ATT&CK'ten Olay Kimliğine eşleşmeler
│   ├── DOCKER_TESTING.md                # Docker test rehberi
│   ├── CI_CD.md                         # CI/CD entegrasyon rehberi
│   └── README.md                        # Dokümantasyon rehberi
├── .github/
│   └── workflows/        # GitHub Actions CI/CD iş akışları
│       ├── windows-docker-tests.yml     # Tam test paketi
│       └── pr-quick-test.yml            # Hızlı PR doğrulaması
├── examples/             # Örnek sorgular ve tespit kuralları (planlanan)
├── tests/                # Otomatik test komut dosyaları (planlanan)
├── Dockerfile            # Windows Server Core konteyneri
├── docker-compose.yml    # Docker Compose yapılandırması
└── readme.md             # Bu dosya
```

## Hızlı Başlangıç

### 1. Denetim Günlüğünü Yapılandırın

İhtiyaçlarınıza göre denetim yapılandırma komut dosyalarından birini seçin:

#### Seçenek A: Kapsamlı Günlük Kaydı (SysmonLikeAudit.ps1)
```powershell
# Yönetici olarak çalıştırın
cd scripts
.\SysmonLikeAudit.ps1
```

**En iyisi:** Ayrıntılı adli analiz, depolamanın kısıtlı olmadığı ortamlar

#### Seçenek B: MITRE ATT&CK Rehberliğinde Günlük Kaydı (win-audit.ps1)
```powershell
# Yönetici olarak çalıştırın
cd scripts
.\win-audit.ps1
```

**En iyisi:** Tehdit avcılığı, azaltılmış yanlış pozitifler, MITRE ATT&CK uyumlu tespit

### 2. Yapılandırmanızı Test Edin

Olayların doğru şekilde oluşturulduğunu doğrulayın:

```powershell
# Temel yapılandırma kontrolü
.\Test-EventIDGeneration.ps1

# Olay oluşturma ile tam test
.\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport

# Analiz için sonuçları dışa aktar
.\Test-EventIDGeneration.ps1 -TestEventGeneration -ExportResults
```

### 3. Test Günlükleri Oluşturun

SIEM ve tespit kurallarınızı test etmek için sentetik günlükler oluşturun:

```powershell
# Kimlik bilgisi dökümü senaryosu oluştur
.\Generate-SyntheticLogs.ps1 -Scenario CredentialDumping -EventCount 100

# Kapsamlı test verisi oluştur
.\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -ExportFormat Both
```

## Docker Testi ve CI/CD

### Docker Konteyner Testi

Tekrarlanabilir, güvenli testler için denetim yapılandırmalarını izole edilmiş Windows konteynerlerinde test edin:

```powershell
# Hızlı başlangıç - Her şeyi oluştur, çalıştır ve test et
.\scripts\Local-DockerTest.ps1 -Action All

# Veya bireysel komutları kullanın
.\scripts\Local-DockerTest.ps1 -Action Build    # Docker imajını oluştur
.\scripts\Local-DockerTest.ps1 -Action Run      # Konteyneri başlat
.\scripts\Local-DockerTest.ps1 -Action Test     # Testleri çalıştır
.\scripts\Local-DockerTest.ps1 -Action Shell    # Etkileşimli kabuk
.\scripts\Local-DockerTest.ps1 -Action Clean    # Temizle
```

**Docker Compose Kullanımı**:
```powershell
# Konteyneri başlat
docker-compose up -d

# Testleri çalıştır
docker-compose exec windows-audit-test powershell -File C:\workspace\scripts\Run-DockerTests.ps1

# Durdur ve kaldır
docker-compose down
```

**Faydalar**:
- **İzole Ortam**: Ana sistemi etkilemeden test edin
- **Tekrarlanabilir**: Makineler arasında tutarlı sonuçlar
- **Otomatik**: GitHub Actions ile tam CI/CD entegrasyonu
- **Güvenli Test**: Potansiyel olarak riskli testleri konteynerlerde çalıştırın

Ayrıntılı Docker test rehberi için [docs/DOCKER_TESTING.md](docs/DOCKER_TESTING.md) dosyasına bakın.

### GitHub Actions CI/CD

Depo, otomatik test iş akışlarını içerir:

**Tam Test Paketi** (`windows-docker-tests.yml`):
- main/develop dallarına push veya pull request yapıldığında tetiklenir
- Windows Docker konteynerini oluşturur
- Paralel test paketlerini çalıştırır (Denetim Yapılandırması, Olay Oluşturma, Sentetik Günlükler, Entegrasyon)
- Kapsamlı test raporları oluşturur
- Sonuçları pull request'lere gönderir

**Hızlı PR Testi** (`pr-quick-test.yml`):
- Pull request'ler için hızlı doğrulama
- PowerShell sözdizimi kontrolü
- Dockerfile doğrulaması
- Dokümantasyon kontrolleri

**Sonuçları Görüntüleme**:
- GitHub'da **Actions** sekmesine gidin
- Ayrıntılı günlükleri ve test sonuçlarını görüntüleyin
- Test yapılarını indirin (JSON sonuçları, sentetik günlükler)
- Test özetleri ile otomatik PR yorumlarını görün

CI/CD entegrasyon ayrıntıları ve özelleştirme için [docs/CI_CD.md](docs/CI_CD.md) dosyasına bakın.

## Denetim Yapılandırma Komut Dosyaları

### SysmonLikeAudit.ps1

Sysmon benzeri günlük kaydı yetenekleri sağlayan kapsamlı Windows denetim ilkesi yapılandırması.

**Etkinleştirir:**
- Nesne Erişimi: Dosyalar, kayıt defteri, çekirdek nesneleri, SAM
- İşlem Oluşturma: Tam komut satırı günlüğü
- Ağ Olayları: Filtreleme Platformu bağlantıları ve paket düşürmeleri
- PowerShell: Modül, komut bloğu ve transkripsiyon günlüğü
- Günlük Ayarları: Üzerine yazma ilkesiyle 32MB günlük boyutları

**Şu durumlarda kullanın:**
- Adli soruşturmalar için maksimum görünürlük
- Olay müdahalesi için kapsamlı günlük kaydı
- Ayrıntılı ağ etkinliği izleme

### win-audit.ps1

Tehdit tespiti için optimize edilmiş MITRE ATT&CK rehberliğinde denetim yapılandırması.

**Etkinleştirir:**
- Gürültülü kategoriler için yalnızca başarı günlüğü (azaltılmış yanlış pozitifler)
- Etki alanı ortamları için Dizin Hizmetleri denetimi
- Kerberos kimlik doğrulama takibi
- Yüksek değerli güvenlik olaylarına odaklanma

**Şu durumlarda kullanın:**
- MITRE ATT&CK çerçevesi uyumu
- Tespit yeteneğinden ödün vermeden azaltılmış günlük hacmi
- Optimize edilmiş tehdit avcılığı yapılandırmaları

## Test ve Doğrulama

### Test-EventIDGeneration.ps1

Denetim yapılandırmasını doğrulayan ve olay oluşturmayı kontrol eden kapsamlı test komut dosyası.

**Özellikler:**
- Tüm denetim ilkesi ayarlarını doğrular
- PowerShell günlük kayıt defteri yapılandırmalarını kontrol eder
- Günlük kaydını doğrulamak için test olayları oluşturur
- Ayrıntılı kapsam raporu sağlar
- Sonuçları JSON olarak dışa aktarır

**Kullanım:**
```powershell
# Yalnızca yapılandırma kontrolü
.\Test-EventIDGeneration.ps1

# Olay oluşturma ile tam doğrulama
.\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport -ExportResults
```

### Generate-SyntheticLogs.ps1

SIEM kurallarını ve tespit mantığını test etmek için gerçekçi Windows Güvenlik Olay günlükleri oluşturur.

**Senaryolar:**
- `CredentialDumping`: LSASS erişimi, kimlik bilgisi hırsızlığı, Kerberos saldırıları
- `LateralMovement`: RDP, SMB, Pass-the-Hash, ağ oturumları
- `PrivilegeEscalation`: UAC atlatma, belirteç manipülasyonu
- `Persistence`: Zamanlanmış görevler, hesap oluşturma, kayıt defteri değişiklikleri
- `Reconnaissance`: Sistem/ağ keşfi, numaralandırma
- `DefenseEvasion`: Günlük kurcalama, gizlenmiş komut dosyaları
- `All`: Tüm senaryolar için olaylar oluştur

**Kullanım:**
```powershell
# Belirli bir senaryo oluştur
.\Generate-SyntheticLogs.ps1 -Scenario LateralMovement -EventCount 200

# Kapsamlı test verisi
.\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -TimeSpan 120
```

## Dokümantasyon

### [EVENT_IDS.md](docs/EVENT_IDS.md)
Tüm Windows Güvenlik Olay Kimlikleri için kapsamlı referans:
- Kategoriye göre düzenlenmiş olay açıklamaları
- İzlenmesi gereken kritik güvenlik olayları
- Tehdit tespiti için olay korelasyon modelleri
- Oturum açma türleri ve ayrıcalık referansı
- Sorgu örnekleri ve analiz ipuçları

### [MITRE_ATTACK_MAPPING.md](docs/MITRE_ATTACK_MAPPING.md)
Windows Olay Kimlikleri ile MITRE ATT&CK çerçevesi arasındaki tam eşleşme:
- MITRE taktiğine göre düzenlenmiş eşleşme tabloları
- Ters arama: Olay Kimliğinden tekniğe
- Örnek sorgularla tespit kullanım durumları
- Kapsam analizi ve boşlukların belirlenmesi
- 10+ ayrıntılı tehdit tespit senaryosu

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici ayrıcalıkları
- Komut dosyası yürütmeye izin veren yürütme ilkesi

## Kullanım Durumları

### Güvenlik Mühendisleri İçin
1. Sağlanan komut dosyalarını kullanarak denetim ilkelerini yapılandırın
2. Tespitleri MITRE ATT&CK çerçevesine eşleyin
3. Sentetik günlüklerle tespit kuralları oluşturun ve test edin
4. SIEM alımını ve ayrıştırmasını doğrulayın

### Tehdit Avcıları İçin
1. Belirli teknikler için ilgili Olay Kimliklerini belirlemek üzere MITRE eşleşmelerini kullanın
2. Av sorguları için tespit kullanım durumlarına başvurun
3. Saldırı zincirlerini belirlemek için olayları ilişkilendirin
4. Sentetik verilerle avlanma hipotezlerini test edin

### Olay Müdahale Ekipleri İçin
1. Soruşturmalar sırasında Olay Kimliği dokümantasyonuna başvurun
2. MITRE eşleşmeleri aracılığıyla saldırgan TTP'lerini anlayın
3. Olay korelasyonlarını kullanarak saldırı zaman çizelgelerini yeniden oluşturun
4. Kapsamlı günlük kaydı ile adli analiz yapın

### Uyumluluk ve Denetim İçin
1. Uyumluluk çerçeveleri için günlük kapsamını gösterin
2. Denetim gereksinimlerini belirli Olay Kimliklerine eşleyin
3. Güvenlik standartlarıyla (NIST, CIS, PCI-DSS) uyumu gösterin
4. Test araçlarıyla denetim etkinliğini doğrulayın

## Kritik Olay Kimlikleri

Olay Kimliklerinin tam listesi için [docs/EVENT_IDS.md](docs/EVENT_IDS.md) dosyasına bakın. Aşağıda tehdit tespiti için en kritik olaylardan bazıları verilmiştir:

### Yüksek Öncelikli Olaylar

| Olay Kimliği | Açıklama | MITRE Taktikleri |
|--------------|----------|------------------|
| **4688** | İşlem Oluşturma | Yürütme, Keşif, Yanal Hareket |
| **4624** | Başarılı Oturum Açma | İlk Erişim, Yanal Hareket |
| **4625** | Başarısız Oturum Açma | İlk Erişim (Kaba Kuvvet) |
| **4672** | Özel Ayrıcalıklar Atandı | Ayrıcalık Yükseltme |
| **4698** | Zamanlanmış Görev Oluşturuldu | Kalıcılık, Yürütme |
| **4768** | Kerberos TGT İsteği | Kimlik Bilgisi Erişimi (Altın Bilet) |
| **4769** | Kerberos Hizmet Bileti | Kimlik Bilgisi Erişimi (Kerberoasting) |
| **5140** | Ağ Paylaşımına Erişildi | Yanal Hareket, Toplama |
| **5156** | Ağ Bağlantısına İzin Verildi | Komuta ve Kontrol, Sızma |
| **4657** | Kayıt Defteri Değiştirildi | Kalıcılık, Savunma Atlatma |
| **4104** | PowerShell Komut Bloğu | Yürütme, Savunma Atlatma |

## Destek

Sorunlar, sorular veya öneriler için:
- GitHub deposunda bir sorun açın
- `/docs` içindeki mevcut dokümantasyonu inceleyin
- Yukarıdaki sorun giderme bölümünü kontrol edin

---

**Sürüm**: 2.0
**Son Güncelleme**: 2025-11-11
