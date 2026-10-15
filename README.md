# Cryptology Security Lab

Egitim amacli guvenli haberlesme ve kriptoloji projesi.

Proje bir sunucu ve ayni client uygulamasinin iki instance'i ile calisir. Client A ve Client B ayni bilgisayarda veya farkli bilgisayarlarda olabilir. Mesaj ve PDF dosyalari guvensiz modda acik, guvenli modda AES-128 ile aktarilir. AES anahtari RSA-2048, DH-2048, ECDH veya ML-KEM ile kurulur.

## Durum

Ilk calisan milestone tamamlandi: insecure TCP modunda Client A -> Server -> Client B plaintext mesaj ve PDF aktarimi yapabiliyor. Server plaintext mesaji konsola basar, PDF'yi `received/` altina kaydeder ve Client B'ye aktarir. AES, key exchange, manuel AES ve Electron henuz uygulanmadi.

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

1. Insecure text ve PDF akisinin hata durumlarini ve Wireshark capture'ini tamamla.
2. Kutuphaneli AES-128-GCM ekle.
3. RSA-OAEP, DH, ECDH ve ML-KEM provider'larini ayni interface arkasina bagla.
4. Manuel AES-128 tek blok deneyini test vektorleriyle dogrula.
5. Her yontem icin 10-15 olcum yapip JSON/CSV yaz.
6. CLI use-case'lerini degistirmeden Electron UI ekle.

## Etik kullanim

Bu proje yalnizca sahibinin kontrolundeki yerel veya acikca izin verilmis lab ortamlarinda kullanilir. Gercek sistemleri taramak, kimlik bilgisi toplamak veya ucuncu taraf trafigini incelemek kapsam disidir.

Detaylar icin [SECURITY.md](SECURITY.md), [mimari notlari](docs/architecture/README.md) ve [katki rehberine](CONTRIBUTING.md) bakin.
