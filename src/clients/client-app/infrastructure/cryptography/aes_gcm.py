"""Client-side AES-128-GCM adapter for encrypting and authenticating payloads."""
# Bu dosya istemci altyapisindaki AES-GCM sifreleme/ cozme sorumlulugunu tasir.
# 16 baytlik AES anahtari disaridan alir; anahtar uretimi ve RSA anahtar paylasimi burada yoktur.
# TCP framing ve server relay de bu dosyanin disindadir; onlar yalnizca nonce ve sifreli veriyi tasir.
# encrypt() (nonce, ciphertext + tag) dondurur; nonce gizli degildir ama ayni anahtarla tekrarlanmamalidir.

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12


class AesGcmAdapter:
    """Disaridan verilen AES-128 session key ile payload sifreler ve dogrulayarak cozer."""

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Yeni nonce uretir ve sifreli veriyi, eklenmis dogrulama tag'iyle dondurur."""
        self._validate_key(key)
        # Nonce acikca karsi tarafa gidebilir; gizli anahtar degildir.
        nonce = os.urandom(NONCE_SIZE_BYTES)
        # AESGCM sonucu ciphertext + 16 baytlik authentication tag seklindedir.
        ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_and_tag

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Tag'i ve varsa AAD'yi dogrular; veri degismisse InvalidTag hatasi verir."""
        self._validate_key(key)
        if len(nonce) != NONCE_SIZE_BYTES:
            raise ValueError(f"AES-GCM nonce must be exactly {NONCE_SIZE_BYTES} bytes.")
        # Kutuphane tag dogrulanmadan plaintext'i dondurmez.
        return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """AES-128 icin anahtarin tam 16 bayt olmasini sifrelemeden once kontrol eder."""
        if len(key) != AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES-128 key must be exactly {AES_KEY_SIZE_BYTES} bytes.")


# Adim adim ornek: ayni session key'i iki tarafta da onceden guvenli sekilde bulunmalidir.
# key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # Yalnizca test anahtari.
# adapter = AesGcmAdapter()
# plaintext = "Merhaba Client B".encode("utf-8")
# aad = b"message-type:text;sender:client-a;receiver:client-b"  # Gizlenmez, dogrulanir.
# nonce, ciphertext_and_tag = adapter.encrypt(key, plaintext, aad)  # 1. Sifrele ve nonce al.
# payload = nonce + ciphertext_and_tag  # 2. Framing ile nonce ve sifreli veriyi gonder.
# received_nonce = payload[:NONCE_SIZE_BYTES]  # 3. Alici ilk 12 bayti nonce olarak ayirir.
# received_ciphertext = payload[NONCE_SIZE_BYTES:]  # 4. Kalan kisim ciphertext + tag'dir.
# message = adapter.decrypt(key, received_nonce, received_ciphertext, aad)  # 5. Dogrula ve coz.
# print(message.decode("utf-8"))  # Merhaba Client B
# AAD kullaniliyorsa gonderen ve alan taraf ayni baytlari vermelidir.