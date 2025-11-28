# Sürüm Notları - v2.0.0

## Yenilikler

Bu sürüm, Windows olay denetimi ve test yeteneklerinde önemli iyileştirmeler ve yeni özellikler sunmaktadır.

### 🚀 Yeni Özellikler

- **Docker Desteği**: İzole edilmiş Windows konteynerlerinde güvenli test imkanı.
  - `Dockerfile` ve `docker-compose.yml` eklendi.
  - `Run-DockerTests.ps1` ve `Local-DockerTest.ps1` yardımcı komut dosyaları.
- **Sentetik Günlük Oluşturucu**: `Generate-SyntheticLogs.ps1` ile gerçekçi saldırı senaryoları (Credential Dumping, Lateral Movement, vb.) oluşturma.
- **Gelişmiş Test Paketi**: `Test-EventIDGeneration.ps1` güncellendi ve kapsamı genişletildi.
- **CI/CD Entegrasyonu**: GitHub Actions ile otomatik test iş akışları (`windows-docker-tests.yml`).

### 🛠️ İyileştirmeler

- **Denetim Komut Dosyaları**: `SysmonLikeAudit.ps1` ve `win-audit.ps1` optimize edildi.
- **Dokümantasyon**: Türkçe README ve Wiki desteği eklendi.
- **Performans**: Docker imajı oluşturma süreci (BuildKit devre dışı bırakılarak) iyileştirildi.

### 🐛 Düzeltmeler

- PowerShell komut dosyalarındaki sözdizimi hataları giderildi.
- Docker birim bağlama (volume mount) sorunları çözüldü.
- `Run-DockerTests.ps1` içindeki parametre çakışması giderildi.

## Kurulum ve Kullanım

1. Depoyu indirin.
2. `scripts` klasöründeki yapılandırma komut dosyalarını Yönetici olarak çalıştırın.
3. Test etmek için `Local-DockerTest.ps1` kullanın.

Daha fazla bilgi için `README.tr.md` ve `docs/WIKI.md` dosyalarına bakın.
