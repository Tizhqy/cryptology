# Infrastructure

Planlanan altyapi:

- Docker Compose ile server ve client servisleri
- Lab-only development CA ve TLS sertifikalari
- Burp proxy ayarlari
- Opsiyonel metrics/log/trace servisleri

Ilk calisma Docker'siz local Python runtime ile yapilir. Iki client ayni bilgisayarda iki process veya farkli bilgisayarlarda ayni config semasi ile calisabilir. Docker Compose daha sonra dependency ve network tekrar edilebilirligi icin eklenir; Wireshark'in host trafigini gormesi ayri test edilir.

Gercek private key dosyalari commit edilmez. Gelistirme sertifikalari script ile uretilir veya acikca lab-only olarak yonetilir.
