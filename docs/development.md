# Development Workflow

## Ilk asama

1. Teknoloji spike'ini tamamla.
2. Secilen stack icin composition root ve minimal health endpoint ekle.
3. Secure client ile ilk authenticated message akisini kur.
4. Insecure client farkini kontrollu lab profiline ekle.
5. Testleri ve Compose altyapisini adim adim ekle.

## Degisiklik sinirlari

Bir ozellik once domain/application sozlesmesi olarak tanimlanir; sonra adapter ve giris noktasina baglanir. Framework kodu domain'e sizdirilmez.

## Git oncesi kontrol

- `.env`, key, certificate private key ve `.pcap` commit edilmemeli.
- Secret taramasi yapilmali.
- Profilin hedef allowlist'i kontrol edilmeli.
- Test ve dokumantasyon guncellenmeli.
