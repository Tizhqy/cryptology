# Technology Spike

## Karar

Ana uygulama dili **Python** olarak secildi. Ilk arayuz CLI olacak; Electron daha sonra ayni application use-case'lerini cagiran masaustu adapter'i olacak.

Rust veya C++ ilk uygulama dili olarak secilmedi. O diller ancak olcumlerde anlamli bir performans darboğazi gorulurse kriptografi/transport adapter'i olarak degerlendirilecek.

## Neden Python?

- TCP socket, CLI, JSON config ve benchmark kodu az boilerplate ile yazilir.
- Python kriptografi ekosisteminde AES, RSA, DH ve ECDH icin olgun kutuphaneler vardir.
- ML-KEM icin kullanilacak paket degisse bile adapter arkasinda saklanabilir.
- Takim arkadaslarinin iki bilgisayarda ayni projeyi kurmasi daha kolaydir.
- Dersin asil yukunu olusturan algoritma mantigi, paket analizi ve rapora daha fazla zaman kalir.

## Neden Rust ilk kapsamda degil?

Rust guvenli ve hizlidir; ancak bu odevde performans ana puan konusu degildir. Rust eklemek iki toolchain, iki dependency sistemi ve Python ile entegrasyon bakimi getirir. Bu, kriptografi mantigini ogrenme ve Wireshark deneylerini geciktirebilir.

## Electron karari

Electron sadece presentation adapter'idir. Renderer HTML/CSS/JavaScript arayuzu gosterir; ana haberlesme ve kriptografi kurallari Electron icine kopyalanmaz. Ilk entegrasyon secenegi local bridge veya local API olarak ayrica kararlastirilacaktir.

Bu karar verilmeden once ayni minimal akisin iki stack ile denenmesi planlanir:

1. Health endpoint
2. Authenticated message endpoint
3. Secure ve insecure client profili
4. Local TLS certificate validation
5. Unit ve integration test
6. Burp proxy ile istek yonlendirme
7. Docker veya yerel calistirma

## Karsilastirma olcutleri

- Ogrenme ve ekip deneyimi
- Standart kriptografi API'lerinin kalitesi
- TLS ve sertifika test edilebilirligi
- Dependency injection ve katman ayrimi
- Windows gelistirme deneyimi
- Docker/Compose entegrasyonu
- Test ve CI sureleri
- Dokumantasyon kolayligi

## Adaylar

- Python + FastAPI
- C# + ASP.NET Core

## Karar

Uygulama spike tamamlandiktan sonra burada kaydedilecektir. Secim, domain ve protokol sozlesmelerini degistirmemelidir.
