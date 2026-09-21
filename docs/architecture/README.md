# Architecture

## Katmanlar

```text
API / Presentation
        |
Application / Use Cases
        |
Domain / Policies
        |
Infrastructure / Adapters
        |
External systems, storage, crypto providers
```

### API / Presentation

HTTP, CLI veya ileride eklenecek web arayuzunun giris noktasi. Request parsing, validation, authentication boundary ve response mapping burada kalir. Is kurali burada uygulanmaz.

### Application

Kullanim senaryolarini orkestre eder. Port/interface tanimlarini kullanir; repository, crypto provider veya HTTP client implementasyonlarina dogrudan baglanmaz.

### Domain

Mesaj, kimlik, imza, guvenlik politikasi ve risk kurallarinin framework'ten bagimsiz modeli. Yan etkisiz ve test edilebilir tutulur.

### Infrastructure

Database, dosya sistemi, TLS, kriptografi kutuphaneleri, dis servisler ve log adapter'lari. Dependency inversion ile application port'larini uygular.

### Observability

Structured log, audit event, metric ve trace. Hassas veri maskeleme bu sinirin zorunlu parcasidir.

## SOLID uygulama kurallari

- **S:** Her class/module tek bir degisime karsi sorumlu olur.
- **O:** Yeni auth veya crypto provider mevcut use-case'i degistirmeden adapter olarak eklenir.
- **L:** Port implementasyonlari sozlesmeyi bozmaz.
- **I:** Buyuk genel interface yerine use-case odakli kucuk portlar kullanilir.
- **D:** Application ve domain concrete infrastructure siniflarini new'lemez; dependency injection kullanir.

## Bagimlilik yonu

Bagimliliklar disaridan iceriye dogru akar. Domain, framework veya database paketini referanslamaz. Shared klasoru domain'in yerine gecmez; yalnizca protokol modelleri ve config semalari icindir.

## Secilen uygulama modeli

```text
Electron GUI (later)
        |
CLI / desktop adapter
        |
Application use-cases
        |
Domain policies + ports
        |
Infrastructure: TCP, AES, RSA, DH, ECDH, ML-KEM, files
```

Client A ve Client B ayni client uygulamasinin farkli JSON config ile calisan iki instance'idir. `secure` ve `insecure` ayri kod tabani degil, ayni transport/protocol akisi icindeki profile secimleridir.

## Veri ve anahtar akisi

```text
RSA / DH / ECDH / ML-KEM
             |
             v
      AES-128 session key
             |
             v
      text or PDF chunks
```

Public-key yontemleri buyuk veriyi sifrelemez. Sunucu Client A verisini kendi session key'iyle acar ve Client B session key'iyle yeniden sifreler.

## Karar kayitlari

- [ADR-0001 teknoloji secimi](adr/0001-technology-selection.md)
- [Teknoloji spike](technology-spike.md)
