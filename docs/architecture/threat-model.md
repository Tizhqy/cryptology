# Threat Model

## Guven siniri

Lab ortami yerel makine veya acikca izin verilmis izole agdir. Guvenliksiz profil bu sinirin disina cikamaz.

## Varliklar

- Kimlik dogrulama verisi
- Mesaj icerigi ve butunlugu
- Imza/sertifika anahtarlari
- Audit kayitlari
- Config ve lab deney sonuclari

## Temel tehditler

- Dinleme ve acik trafik
- Mesaj degistirme
- Replay
- Gecersiz veya yanlis sertifika kabulü
- Yetkisiz endpoint erisimi
- Secret'in log veya repository'ye sizmasi

## Beklenen kontroller

- TLS certificate validation
- Authentication ve authorization
- Message integrity / signature validation
- Replay protection
- Structured audit ve sensitive field masking
- Lab target allowlist
- Production ortaminda insecure profile reddi

Her yeni deney bu listeye hangi tehdidi gosterdigini ve hangi kontrolde karsilik buldugunu eklemelidir.
