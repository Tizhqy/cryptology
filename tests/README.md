# Tests


Zorunlu ilk testler:

- Config'teki `max_file_size_bytes`, `chunk_size_bytes` ve `repeat_count` validation'i.
- Ayni input/key icin manuel AES ve kutuphaneli single-block AES esitligi.
- Her key exchange provider'in iki tarafta ayni 16-byte session key'i uretmesi.
- Server relay'in Client A key'iyle acip Client B key'iyle yeniden sifrelemesi.
- PDF chunk sirasi, boyut limiti ve SHA-256 butunluk kontrolu.

Secilecek teknolojiye gore test runner ve CI komutlari burada belgelenecektir.
