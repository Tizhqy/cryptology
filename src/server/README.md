# Server

`main.py` su an insecure milestone'u calistirir: iki client baglantisini kabul eder, plaintext text/PDF frame'lerini Client A ile Client B arasinda aktarir. Text'i konsola basar, PDF'yi `received/` altina kaydeder. Encryption ve key exchange sonraki milestone'lardir.

Planlanan alt sinirlar:

- `api`: HTTP/CLI giris noktasi ve response mapping
- `application`: Use-case handler/service'leri
- `domain`: Guvenlik politikasi ve domain modelleri
- `infrastructure`: Storage, crypto, network ve dis adapter'lar
- `observability`: Log, audit, metric ve trace

Calistirma: `python src/server/main.py --config config/server.json --mode insecure`
