"""PSEUDOCODE: Server crypto adapter secimi."""


def build_crypto_registry(settings):
    # Data cipher her zaman AES-128 olur; key exchange degisebilir.
    data_cipher = AesGcmAdapter(key_size=16)

    key_exchange_providers = {
        "rsa-oaep": RsaOaepKeyExchange(),
        "dh-2048": Dh2048KeyExchange(kdf=HkdfSha256()),
        "ecdh": EcdhKeyExchange(kdf=HkdfSha256()),
        "ml-kem-768": MlKemKeyExchange(provider=load_mlkem_provider()),
    }

    return CryptoRegistry(data_cipher, key_exchange_providers)
