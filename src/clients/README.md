# Clients

Ayni protokol sozlesmesini kullanan istemci profilleri.

- `secure-client`: Guvenli varsayilanlar ve TLS certificate validation.
- `insecure-client`: Yalnizca lab profili; kontrollu farklari gozlemlemek icin.

Istemciler ortak kodu gereksizce paylasarak guvenlik farkini gizlememeli; yalnizca protocol model ve transport abstraction ortaklastirilmalidir.
