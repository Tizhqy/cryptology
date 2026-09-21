# Contributing

## Gelistirme kurallari

- Degisiklikleri tek sorumluluk etrafinda kucuk tutun.
- Controller icine is kurali koymayin.
- Domain katmanini framework ve dis servislerden bagimsiz tutun.
- Yeni guvenlik davranisi icin pozitif ve negatif test ekleyin.
- Guvenliksiz davranis ekliyorsaniz bunun yalnizca lab profili oldugunu ve production'da reddedildigini belgeleyin.
- Secret, private key, `.env` veya `.pcap` dosyasi commit etmeyin.

## Commit onerisi

`area: short imperative description`

Ornek: `docs: add TLS observation lab notes`

Teknoloji secildikten sonra format, lint, test ve CI komutlari bu dosyaya eklenecektir.
