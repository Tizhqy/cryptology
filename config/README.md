# Configuration

Config dosyalari environment'a gore secilir; secret degerler dosyaya yazilmaz. Ana uygulama `server.json`, `client-a.json` veya `client-b.json` yukler; deney profili bu ayarlarin uzerine merge edilir.

Planlanan profiller:

- `base`: Ortak varsayilanlar
- `secure`: TLS, auth, integrity ve production-like kontroller
- `insecure`: Yalnizca izole lab icin kontrollu acik payload
- `secure-rsa`, `secure-dh`, `secure-ecdh`, `secure-mlkem`: AES session key kurma profilleri
- `experiments/manual-aes`: Gercek haberlesmeden ayri manuel AES profili

Config yukleme kodu, application katmanina concrete config kaynagi olarak sizmamali; typed config portu veya immutable settings modeli kullanilmalidir. CLI ve ileride Electron sadece config yolunu/override'i verir.
