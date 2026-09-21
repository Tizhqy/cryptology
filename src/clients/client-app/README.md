# Client Application

Bu klasor Client A ve Client B olarak iki instance calisan tek client uygulamasinin core taslagidir.

- `application`: send text, send PDF, connect ve key exchange use-case'leri.
- `domain`: client identity, transfer state ve validation kurallari.
- `infrastructure`: TCP, crypto, PDF chunking ve measurement adapter'lari.
- `cli`: ilk kullanici arayuzu.
- `gui-bridge`: ileride Electron main process ile baglanti siniri.

Client A/B ayrimi kod kopyasi ile degil, `config/client-a.json` ve `config/client-b.json` ile yapilir.
