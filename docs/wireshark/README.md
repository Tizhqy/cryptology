# Wireshark Plan

Her senaryo icin server ve client tarafinda capture alinmasi planlanir.

## Senaryolar

- `insecure-text`: TCP payload icinde test metni okunabilir.
- `secure-rsa`: RSA-OAEP key exchange, ardindan AES-GCM payload.
- `secure-dh`: DH-2048 public values ve AES-GCM payload.
- `secure-ecdh`: ECDH public values ve AES-GCM payload.
- `secure-mlkem`: ML-KEM encapsulation payload ve AES-GCM payload.
- `secure-pdf`: PDF chunk metadata, sifreli payload ve ACK.

Gercek capture dosyalari `captures/` altinda yerel tutulur. Rapor icin paket boyutu, plaintext gorunurlugu ve key exchange trafigi ekran goruntuleri hazirlanir.
