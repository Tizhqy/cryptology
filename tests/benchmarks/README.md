# Benchmark Tests

RSA-2048, DH-2048, ECDH ve ML-KEM-768 icin 15 tekrarli olcumler burada dogrulanir.

Olcumler:

- Key generation milliseconds
- Key exchange milliseconds
- Exchange frame/network byte count

Ham sonuclar JSON, ozet sonuclar CSV olarak `artifacts/measurements` altina yazilir. Gercek cihaz sonucu alinmadan rapora sabit sayi yazilmaz.
