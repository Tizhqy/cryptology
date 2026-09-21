# Cryptology Security Lab

Egitim amacli guvenli haberlesme ve kriptoloji projesi.

Proje bir sunucu ve ayni client uygulamasinin iki instance'i ile calisir. Client A ve Client B ayni bilgisayarda veya farkli bilgisayarlarda olabilir. Mesaj ve PDF dosyalari guvensiz modda acik, guvenli modda AES-128 ile aktarilir. AES anahtari RSA-2048, DH-2048, ECDH veya ML-KEM ile kurulur.

## Durum

Bu depo Python merkezli taslak asamasindadir. Once CLI akisi ve core use-case'ler kurulacak, daha sonra ayni use-case'leri cagiran Electron arayuzu eklenecektir. Rust veya C++ ilk kapsamda yoktur; ancak ileride performans ihtiyaci olursa infrastructure adapter'i olarak eklenebilir.

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

## Baslangic

Ilk teknik adim Python ile CLI server/client akisini kurmaktir. Ornek config'ler `config/` altindadir. Uygulama kodu eklendiginde kurulum komutlari ve Electron gelistirme komutlari bu README'ye eklenecektir.

## Uygulama sirasi

1. TCP framing ve server relay pseudocode'unu gercek Python koduna cevir.
2. Tek client'i Client A/B config'leriyle calistir.
3. Guvensiz text ve PDF chunk transferini tamamla.
4. Kutuphaneli AES-128-GCM ekle.
5. RSA-OAEP, DH, ECDH ve ML-KEM provider'larini ayni interface arkasina bagla.
6. Manuel AES-128 tek blok deneyini test vektorleriyle dogrula.
7. 10-15 tekrar olcumlerini JSON/CSV yaz.
8. CLI use-case'lerini degistirmeden Electron UI ekle.

## Etik kullanim

Bu proje yalnizca sahibinin kontrolundeki yerel veya acikca izin verilmis lab ortamlarinda kullanilir. Gercek sistemleri taramak, kimlik bilgisi toplamak veya ucuncu taraf trafigini incelemek kapsam disidir.

Detaylar icin [SECURITY.md](SECURITY.md), [mimari notlari](docs/architecture/README.md) ve [katki rehberine](CONTRIBUTING.md) bakin.
