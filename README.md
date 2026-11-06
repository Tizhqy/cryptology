## Grup Projesi

| Ogrenci No | Ad Soyad | GitHub |
| --- | --- | --- |
| 445841 | Yusuf Tan DURMUŞ | YusufTanDURMUS |
| 458364 | Mehmet Eren BAYRAKTAR | Tizhqy |
| 445851 | Ömer Eren HALİLOĞLU | ? |

Yusuf git hesabinda bir yanlislik yapmis ve commitleri yanlis sekilde atmis. merge edilen commitlerde Tizhqy disindaki commitler "Yusuf" bundan sonra YusufTanDurmus hesabiyle commit atmaya devam edecek. İkisi de ayni kisi yani.

# Cryptology Security Lab

Egitim amacli guvenli haberlesme ve kriptoloji projesi.

Proje bir sunucu ve ayni client uygulamasinin iki instance'i ile calisir. Client A ve Client B ayni bilgisayarda veya farkli bilgisayarlarda olabilir. Mesaj ve PDF dosyalari guvensiz modda acik, guvenli modda AES-128 ile aktarilir. AES anahtari RSA-2048, DH-2048, ECDH veya ML-KEM ile kurulur.

## Durum

Ilk calisan milestone tamamlandi: insecure TCP modunda Client A -> Server -> Client B plaintext mesaj ve PDF aktarimi yapabiliyor. Manuel AES-128/192/256 deneyleri test vektorleriyle dogrulandi. Client tarafinda AES-128-GCM adapter'i ve unit testleri de hazir; ancak bu adapter henuz client/server mesaj akisina bagli degil. RSA key exchange, secure text/PDF aktarimi ve Electron henuz tamamlanmadi.

## Tamamlanan Dosyalar

- `src/shared/protocol/framing.py`: TCP byte akisina 4-byte header uzunlugu, JSON header ve binary payload yapisini ekler; tam frame gonderip alir.
- `src/server/main.py`: Server config'ini yukler ve relay server'i baslatir.
- `src/server/relay.py`: Client kaydi alir, `receiver_id` ile yonlendirme yapar, plaintext mesaji konsola yazar; PDF parcalarini kaydeder, boyut/hash kontrolu yapar ve aliciya aktarir.
- `src/clients/client-app/main.py`: Client'i server'a baglar; metin gonderir, PDF'yi parcalara ayirir, gelen PDF'yi yeniden kurup hash'ini dogrular.
- `config/server.json`, `config/client-a.json`, `config/client-b.json`: Server adresi, port, client kimligi ve transfer limitlerini tanimlar.
- `tests/integration/test_insecure_relay.py`: Insecure text/PDF relay, ACK, client kapanisi ve PDF yeniden kurma akislarini test eder.
- `experiments/manual_aes/mehmet_aes.py`, `experiments/manual_aes/yusuf_aes.py`: Uygulama ag akisindan bagimsiz manuel AES deneyleri.
- `tests/experiments/test_mehmet_aes.py`, `tests/experiments/test_manual_aes.py`: Manuel AES test vektorlerini, round-trip ve ilgili matematik kontrollerini test eder.
- `src/clients/client-app/infrastructure/cryptography/aes_gcm.py`: Client tarafinda AES-128-GCM encrypt/decrypt, nonce ve AAD destegi saglar. Henuz `main.py` tarafindan cagrilmadigi icin secure mode'u tek basina etkinlestirmez.
- `tests/unit/test_client_aes_gcm.py`: AES-GCM round-trip, nonce, AAD, degistirilmis ciphertext ve gecersiz anahtar testleri.

## Insecure Aktarim Akisi

1. `src/server/main.py`, `config/server.json` dosyasindan `0.0.0.0:5050` adresini ve transfer limitlerini okur; relay server'i baslatir.
2. Client A ve Client B, kendi JSON config dosyalarindaki server adresine baglanir ve `register` frame'iyle client kimliklerini bildirir.
3. Client A metin gonderirken metni UTF-8 byte'larina cevirir. `send_frame()` JSON header'a payload uzunlugunu ekler ve header ile payload'i TCP uzerinden yollar.
4. Server `receive_frame()` ile frame'i alir. `relay.py`, `receiver_id` ile Client B'yi bulur; plaintext'i konsola yazar, ayni payload'i B'ye iletir ve A'ya ACK gonderir.
5. PDF aktariminda Client A once `file_start` metadata frame'ini, ardindan sirali `file_chunk` frame'lerini ve son olarak `file_complete` frame'ini yollar.
6. Server her chunk'in sirasini ve boyutunu kontrol eder, PDF'yi `received/` altina yazar ve aliciya aktarir. Tamamlaninca toplam boyut ve SHA-256 degerini dogrular.
7. Client B chunk'lari `downloads/` altinda yeniden birlestirir ve SHA-256 degerini kontrol eder. Bu modda payload sifresiz oldugu icin Wireshark'ta okunabilir.

AES-GCM adapter'i bu akistan henuz cagrilmaz. Guvenli akista her client'in ayri AES session key'i olacak; server A'dan gelen veriyi A'nin key'iyle cozecek ve B'ye B'nin key'iyle yeniden sifreleyecek. Nonce ve ciphertext/tag frame payload'inda tasinacak; key exchange ve server adapter'i henuz yapilmadi.

## Mimari ilkeler

- API/controller katmani ince kalir; is kurali `application` katmaninda uygulanir.
- `domain` dis sistemleri ve frameworkleri bilmez.
- Dis bagimliliklar `infrastructure` adapter'lariyla sisteme girer.
- Tek client uygulamasi guvenli/güvensiz davranisi config profiliyle secer; iki ayri client kodu kopyalanmaz.
- Kriptografi deneyleri uretim akisi disinda tutulur.
- Uretim haberlesmesi kutuphaneli AES-128-GCM kullanir; manuel AES ayri deney ve test modudur.
- RSA, DH, ECDH ve ML-KEM yalnizca AES session key kurmak icin kullanilir; PDF dogrudan public-key algoritmasiyla sifrelenmez.
- Config JSON ile tekrar edilebilir deneyler, 10-15 olcum ve JSON/CSV rapor ciktilari uretilir.
- Secret, private key, kisisel veri ve trafik kaydi repoya girmez.
- Guvenliksiz profil sadece izole egitim ortami ve allowlist hedefler icin etkin olabilir.

## Klasorler

- `src/server`: Sunucu ve katmanli uygulama.
- `src/clients`: Tek client core'u, CLI adapter'i ve ileride Electron bridge'i.
- `src/shared`: API sozlesmeleri, ortak modeller ve config semalari.
- `experiments`: Haftalik kriptoloji deneyleri.
- `tests`: Unit, integration, contract ve security regression testleri.
- `config`: Server, Client A/B ve guvenli/güvensiz/key-exchange profilleri.
- `desktop/electron`: Core'a baglanan opsiyonel masaustu arayuzu taslagi.
- `infra`: Docker, TLS lab ve gozlemleme altyapisi.
- `docs`: Mimari kararlar, tehdit modeli ve deney notlari.
- `scripts`: Tekrarlanabilir gelistirme ve kontrol komutlari.

## Baslangic (Windows)

Python 3.11 veya ustunu kullanin. Ilk milestone runtime icin harici paket gerektirmez. Test icin `python -m pip install -r requirements.txt` calistirin.

1. Terminal 1'de sunucuyu baslatin:

```powershell
python src/server/main.py --config config/server.json --mode insecure
```

2. Terminal 2'de Client B'yi baslatin:

```powershell
python src/clients/client-app/main.py --config config/client-b.json --mode insecure
```

3. Terminal 3'te Client A'yi baslatin:

```powershell
python src/clients/client-app/main.py --config config/client-a.json --mode insecure
```

Client A'da normal yazi mesaj gonderir. PDF icin `/file "C:\\path\\sample.pdf"`, cikmak icin `/quit` yazin. Client B gelen mesaji ve dosyayi alir. Server'in durdugu bilgisayarda `received/`, Client B'de `downloads/` olusur.

Iki farkli bilgisayarda calistirirken `client-a.json` ve `client-b.json` icindeki `server_host` degerini Server bilgisayarinin LAN IP adresi yapin; TCP 5050 icin yerel firewall izni gerekebilir. Ilk Wireshark denemelerini yalnizca kendi bilgisayarlarinizda ve sentetik veriyle yapin.

## Test

```powershell
python -m pytest tests/integration/test_insecure_relay.py -q
```

## Uygulama sirasi

1. Insecure baseline icin iki bilgisayarda Wireshark kaydi alip `.pcapng` dosyalarini `captures/` altina koy.
2. RSA-OAEP ile her client icin AES-128 session key kurulumunu ekle ve key exchange testlerini yaz.
3. Server infrastructure katmanina AES-GCM adapter'i ekle; client ve server adapter'larini secure text akisina bagla.
4. Secure PDF aktariminda her chunk'i sifrele; nonce, metadata/AAD, tag dogrulamasi ve hata durumlarini test et.
5. Insecure testlerin bozulmadigini, secure text/PDF round-trip ve degistirilmis ciphertext'in reddedildigini dogrula; sonra ikinci Wireshark kaydini al.
6. DH-2048, ECDH ve ML-KEM-768 key exchange provider'larini ayni sozlesmeye ekle; her yontem icin 10 olcum alip sure ve paket boyutu ortalamalarini JSON/CSV'ye yaz.
7. Manuel AES raporunu, Wireshark analizini ve gorev dagilimini tamamla; masaustu arayuzunu (Electron veya baska secenek) core kararlastiktan sonra ele al.

## Etik kullanim

Bu proje yalnizca sahibinin kontrolundeki yerel veya acikca izin verilmis lab ortamlarinda kullanilir. Gercek sistemleri taramak, kimlik bilgisi toplamak veya ucuncu taraf trafigini incelemek kapsam disidir.

Detaylar icin [SECURITY.md](SECURITY.md), [mimari notlari](docs/architecture/README.md) ve [katki rehberine](CONTRIBUTING.md) bakin.
