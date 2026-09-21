# ADR-0002: Python Core, CLI First, Electron Later

- Status: Accepted
- Date: 2026-09-21

## Context

Odev bir sunucu, iki client instance'i, text/PDF transferi, dört key exchange yontemi, manuel AES, benchmark ve Wireshark analizi istiyor. Masaustu arayuzu sunum kolayligi saglayabilir; ancak core haberlesme ve kriptografi mantigini buyutmewemelidir.

## Decision

Python core uygulama dili olarak secildi. Ilk kullanici arayuzu CLI olacak. Electron, core use-case'lerini cagiran opsiyonel desktop adapter'i olarak daha sonra eklenecek. Client A ve Client B ayni uygulamanin JSON config ile calisan instance'laridir.

## Consequences

- Ilk gelistirme ve debug daha az boilerplate ile ilerler.
- GUI gecikse bile odevin server/client ve Wireshark akisi calisabilir.
- Electron renderer icinde kriptografi veya TCP kodu tekrarlanmaz.
- Rust/C++ ancak olcumlerle kanitlanmis performans ihtiyacinda adapter olarak degerlendirilir.
