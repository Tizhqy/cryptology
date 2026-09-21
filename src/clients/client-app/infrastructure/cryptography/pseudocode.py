"""PSEUDOCODE: Client crypto abstraction."""


class KeyExchangeProvider:
    def establish_with_server(self, transport) -> bytes:
        # Her provider ayni sonucu vermeli: 16 byte AES session key.
        raise NotImplementedError()


class RsaOaepKeyExchange(KeyExchangeProvider):
    def establish_with_server(self, transport):
        aes_key = random_bytes(16)
        server_public_key = transport.request_server_public_key()
        wrapped_key = rsa_oaep_encrypt(server_public_key, aes_key)
        transport.send_key_exchange(wrapped_key)
        return aes_key


class Dh2048KeyExchange(KeyExchangeProvider):
    def establish_with_server(self, transport):
        private_value, public_value = generate_dh_2048_key_pair()
        peer_public_value = transport.exchange_public_value(public_value)
        shared_secret = calculate_dh_shared_secret(private_value, peer_public_value)
        return hkdf_sha256(shared_secret, length=16, info=b"cryptology-lab")


class EcdhKeyExchange(KeyExchangeProvider):
    def establish_with_server(self, transport):
        private_key, public_key = generate_ecdh_key_pair()
        peer_public_key = transport.exchange_public_value(public_key)
        shared_secret = calculate_ecdh_shared_secret(private_key, peer_public_key)
        return hkdf_sha256(shared_secret, length=16, info=b"cryptology-lab")


class MlKemKeyExchange(KeyExchangeProvider):
    def establish_with_server(self, transport):
        public_key = transport.request_mlkem_public_key()
        ciphertext, shared_secret = mlkem_encapsulate(public_key)
        transport.send_mlkem_ciphertext(ciphertext)
        return hkdf_sha256(shared_secret, length=16, info=b"cryptology-lab")
