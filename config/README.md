# Configuration

Config dosyalari environment'a gore secilir; secret degerler dosyaya yazilmaz.

Planlanan profiller:

- `base`: Ortak varsayilanlar
- `secure`: TLS, auth, integrity ve production-like kontroller
- `insecure`: Yalnizca izole lab icin kontrollu zayiflikler
- `proxy`: Burp gibi yerel proxy icin ayarlar

Config yukleme kodu, application katmanina concrete config kaynagi olarak sizmamali; typed config portu veya immutable settings modeli kullanilmalidir.
