# Cryptography Experiments

Ders haftalarina karsilik bagimsiz deneyler burada tutulur:

- Modular arithmetic and number theory
- DES and AES concepts
- Hash algorithms and MD5 limitations
- RSA and El Gamal
- Elliptic curve cryptography
- Digital signatures
- Certificates and TLS

Deney kodu, uretim uygulamasinda kullanilacak kriptografik uygulamanin yerine gecmez. Standart kutuphaneler ve bilinen test vektorleri tercih edilir.

## Odev deneyleri

- `manual_aes`: AES-128 round, S-box, ShiftRows, MixColumns ve key expansion.
- `benchmarks`: RSA, DH, ECDH ve ML-KEM icin 10-15 tekrarli olcum.
- `library_aes`: Kutuphaneli AES-128-GCM davranisi ve nonce/tag notlari.

Manuel AES once tek 16-byte block icin dogrulanir. CBC veya GCM gibi modlar ancak bu sonuc test vektorleriyle eslestikten sonra ayri deney olarak eklenir.
