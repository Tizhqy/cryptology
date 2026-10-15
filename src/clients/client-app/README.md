# Client Application

Bu klasor Client A ve Client B olarak iki instance calisan tek client uygulamasidir. Ilk milestone'da plaintext text ve PDF gonderip alabilir.

- `application`: send text, send PDF, connect ve key exchange use-case'leri.
- `domain`: client identity, transfer state ve validation kurallari.
- `infrastructure`: TCP, crypto, PDF chunking ve measurement adapter'lari.
- `cli`: ilk kullanici arayuzu.
- `gui-bridge`: ileride Electron main process ile baglanti siniri.

Client A/B ayrimi kod kopyasi ile degil, `config/client-a.json` ve `config/client-b.json` ile yapilir.

Ornek: `python src/clients/client-app/main.py --config config/client-a.json --mode insecure`
