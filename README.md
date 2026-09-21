# Cryptology Security Lab

Egitim amacli bilgi guvenligi ve kriptoloji laboratuvari.

Proje, ayni sunucuya baglanan guvenli ve kontrollu guvenliksiz istemci profillerini karsilastirmak; trafik, kimlik dogrulama, butunluk, TLS ve audit davranisini Wireshark/Burp gibi araclarla gozlemlemek icin tasarlanir.

## Durum

Bu depo su anda teknoloji bagimsiz temel iskelet asamasindadir. Uygulama dili ve framework, kucuk bir karar spike'inda belirlenecektir. Domain, config, test ve dokumantasyon sinirlari bu karardan bagimsiz tutulur.

## Mimari ilkeler

- API/controller katmani ince kalir; is kurali `application` katmaninda uygulanir.
- `domain` dis sistemleri ve frameworkleri bilmez.
- Dis bagimliliklar `infrastructure` adapter'lariyla sisteme girer.
- Guvenli ve guvenliksiz istemciler ortak protokolu kullanir, guvenlik davranisini birbirine kopyalamaz.
- Kriptografi deneyleri uretim akisi disinda tutulur.
- Secret, private key, kisisel veri ve trafik kaydi repoya girmez.
- Guvenliksiz profil sadece izole egitim ortami ve allowlist hedefler icin etkin olabilir.

## Klasorler

- `src/server`: Sunucu ve katmanli uygulama.
- `src/clients`: Guvenli ve kontrollu guvenliksiz istemciler.
- `src/shared`: API sozlesmeleri, ortak modeller ve config semalari.
- `experiments`: Haftalik kriptoloji deneyleri.
- `tests`: Unit, integration, contract ve security regression testleri.
- `config`: Ortak ve profil bazli ayarlar.
- `infra`: Docker, TLS lab ve gozlemleme altyapisi.
- `docs`: Mimari kararlar, tehdit modeli ve deney notlari.
- `scripts`: Tekrarlanabilir gelistirme ve kontrol komutlari.

## Baslangic

Teknoloji karari verilmeden uygulama komutu eklenmeyecektir. Ilk teknik adim, `docs/architecture/technology-spike.md` icindeki olcutlerle Python/FastAPI ve C#/ASP.NET Core seceneklerini karsilastirmaktir.

## Etik kullanim

Bu proje yalnizca sahibinin kontrolundeki yerel veya acikca izin verilmis lab ortamlarinda kullanilir. Gercek sistemleri taramak, kimlik bilgisi toplamak veya ucuncu taraf trafigini incelemek kapsam disidir.

Detaylar icin [SECURITY.md](SECURITY.md), [mimari notlari](docs/architecture/README.md) ve [katki rehberine](CONTRIBUTING.md) bakin.
