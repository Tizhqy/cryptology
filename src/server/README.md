# Server

Sunucu uygulamasi burada yer alir. Iki client baglantisini kabul eder, gelen text/PDF frame'lerini gonderen client key'i ile acar, plaintext'i konsola basar ve hedef client key'iyle yeniden sifreleyerek iletir.

Planlanan alt sinirlar:

- `api`: HTTP/CLI giris noktasi ve response mapping
- `application`: Use-case handler/service'leri
- `domain`: Guvenlik politikasi ve domain modelleri
- `infrastructure`: Storage, crypto, network ve dis adapter'lar
- `observability`: Log, audit, metric ve trace

Ilk giris noktasi TCP server'dir. Framework veya HTTP bridge daha sonra eklenebilir; application use-case'leri bu secime bagli olmamalidir.
