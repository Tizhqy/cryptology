# Clients

Client A ve Client B, `src/clients/client-app` altindaki ayni uygulamanin iki instance'idir. Fark, `config/client-a.json` ve `config/client-b.json` dosyalarindaki `client_id` degeridir.

- `client-app`: Gercek application, CLI ve infrastructure taslagi.
- `secure-client`: Ilk planlama doneminden kalan uyumluluk klasoru; guvenli profile ait notlar icin tutulur.
- `insecure-client`: Ilk planlama doneminden kalan uyumluluk klasoru; guvensiz profile ait notlar icin tutulur.

Guvensiz davranis ayri client kodu olarak kopyalanmaz. Ayni protocol ve transport akisinda config secimiyle belirlenir.
