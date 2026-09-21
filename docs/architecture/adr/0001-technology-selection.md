# ADR-0001: Technology Selection

- Status: Proposed
- Date: 2026-09-21

## Context

Proje, guvenli ve kontrollu guvenliksiz istemcilerin baglandigi bir lab sunucusu, trafik gozlemi ve kriptoloji deneyleri icerecek. Dil secimi henuz kesin degil.

## Decision

Dil ve web framework'u, `technology-spike.md` icindeki ayni davranis setiyle karsilastirildiktan sonra secilecek. Domain, application port'lari, config semalari ve test niyeti secimden bagimsiz tutulacak.

## Consequences

- Ilk iskelet framework dosyalarina bagli degildir.
- Karar sonrasi sadece composition root, adapter ve uygulama giris noktalarinin eklenmesi gerekir.
- CI ve container komutlari karar sonrasinda kesinlestirilir.
