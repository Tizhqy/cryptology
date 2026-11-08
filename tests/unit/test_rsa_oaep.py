"""Unit and Roundtrip Tests for RSA-OAEP Key Exchange."""

import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src.shared.crypto.rsa_oaep import (
    RSAKeyExchangeServer,
    RSAKeyExchangeClient,
)


class TestRSAKeyExchangeServer:
    """Tests for server-side key generation, serialization, and deserialization."""

    def test_default_key_generation(self) -> None:
        """Verify server generates a valid 2048-bit RSA key pair by default."""
        server = RSAKeyExchangeServer()
        assert server.private_key is not None
        assert server.public_key is not None
        assert server.private_key.key_size == 2048

    def test_custom_key_generation_valid(self) -> None:
        """Verify server supports custom valid key sizes >= 2048 bits."""
        key = RSAKeyExchangeServer.generate_key_pair(key_size=2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_key_generation_rejects_insecure_size(self) -> None:
        """Verify server raises ValueError for key sizes less than 2048 bits."""
        with pytest.raises(ValueError, match="at least 2048 bits"):
            RSAKeyExchangeServer.generate_key_pair(key_size=1024)

    def test_public_key_pem_export(self) -> None:
        """Verify public key exports to standard SubjectPublicKeyInfo PEM."""
        server = RSAKeyExchangeServer()
        pem = server.export_public_key_pem()
        assert isinstance(pem, bytes)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert pem.strip().endswith(b"-----END PUBLIC KEY-----")

    def test_private_key_pem_export_and_load_unencrypted(self) -> None:
        """Verify private key roundtrip export and loading without password."""
        server = RSAKeyExchangeServer()
        pem = server.export_private_key_pem()
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

        loaded_server = RSAKeyExchangeServer.from_private_key_pem(pem)
        assert loaded_server.private_key.key_size == server.private_key.key_size
        assert loaded_server.export_public_key_pem() == server.export_public_key_pem()

    def test_private_key_pem_export_and_load_with_password(self) -> None:
        """Verify private key export with encryption and loading with password."""
        server = RSAKeyExchangeServer()
        password = b"secret-passphrase"
        pem = server.export_private_key_pem(password=password)
        assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

        # Wrong password fails
        with pytest.raises(Exception):
            RSAKeyExchangeServer.from_private_key_pem(pem, password=b"wrong-pass")

        # Correct password succeeds
        loaded_server = RSAKeyExchangeServer.from_private_key_pem(pem, password=password)
        assert loaded_server.export_public_key_pem() == server.export_public_key_pem()


class TestRSAKeyExchangeClient:
    """Tests for client-side AES key generation and OAEP wrapping."""

    @pytest.fixture
    def server(self) -> RSAKeyExchangeServer:
        return RSAKeyExchangeServer()

    @pytest.fixture
    def client(self, server: RSAKeyExchangeServer) -> RSAKeyExchangeClient:
        return RSAKeyExchangeClient.from_public_key_pem(server.export_public_key_pem())

    def test_client_init_type_error(self) -> None:
        """Verify TypeError when initialized with invalid public key."""
        with pytest.raises(TypeError):
            RSAKeyExchangeClient(server_public_key="not-a-key")  # type: ignore

    def test_generate_aes_key_sizes(self) -> None:
        """Verify generation of valid 16, 24, and 32 byte AES keys."""
        k16 = RSAKeyExchangeClient.generate_aes_key(16)
        k24 = RSAKeyExchangeClient.generate_aes_key(24)
        k32 = RSAKeyExchangeClient.generate_aes_key(32)

        assert len(k16) == 16
        assert len(k24) == 24
        assert len(k32) == 32
        assert k16 != RSAKeyExchangeClient.generate_aes_key(16)  # High entropy check

    def test_generate_aes_key_invalid_size(self) -> None:
        """Verify ValueError for unsupported AES key sizes."""
        with pytest.raises(ValueError, match="Invalid AES key size"):
            RSAKeyExchangeClient.generate_aes_key(12)

    def test_wrap_aes_key_validations(self, client: RSAKeyExchangeClient) -> None:
        """Verify validation on AES key type and size before wrapping."""
        with pytest.raises(TypeError):
            client.wrap_aes_key("not-bytes")  # type: ignore

        with pytest.raises(ValueError, match="length must be 16"):
            client.wrap_aes_key(b"short-key")

    def test_wrap_aes_key_produces_rsa_size_ciphertext(self, client: RSAKeyExchangeClient) -> None:
        """Verify 2048-bit RSA key produces exactly 256-byte ciphertext."""
        raw_key, wrapped_key = client.generate_and_wrap_key(key_size=16)
        assert len(raw_key) == 16
        assert len(wrapped_key) == 256


class TestRSAOAEPKeyExchangeRoundtrip:
    """End-to-end roundtrip verification between Client and Server."""

    def test_successful_16_byte_aes_roundtrip(self) -> None:
        """Verify client 16-byte AES-128 key is wrapped and recovered cleanly by server."""
        server = RSAKeyExchangeServer()
        client = RSAKeyExchangeClient.from_public_key_pem(server.export_public_key_pem())

        original_aes_key, wrapped_key = client.generate_and_wrap_key(key_size=16)
        recovered_aes_key = server.unwrap_aes_key(wrapped_key)

        assert recovered_aes_key == original_aes_key
        assert len(recovered_aes_key) == 16

    def test_successful_24_and_32_byte_aes_roundtrip(self) -> None:
        """Verify roundtrip works for AES-192 and AES-256 keys as well."""
        server = RSAKeyExchangeServer()
        client = RSAKeyExchangeClient(server.public_key)

        for size in (24, 32):
            raw_key, wrapped_key = client.generate_and_wrap_key(key_size=size)
            recovered_key = server.unwrap_aes_key(wrapped_key)
            assert recovered_key == raw_key
            assert len(recovered_key) == size

    def test_unwrap_with_tampered_ciphertext_fails(self) -> None:
        """Verify tampering with ciphertext prevents unwrapping (OAEP integrity failure)."""
        server = RSAKeyExchangeServer()
        client = RSAKeyExchangeClient(server.public_key)

        _, wrapped_key = client.generate_and_wrap_key(key_size=16)

        # Flip bytes in ciphertext
        tampered_key = bytearray(wrapped_key)
        tampered_key[10] ^= 0xFF
        tampered_key = bytes(tampered_key)

        with pytest.raises(ValueError, match="Failed to unwrap AES key"):
            server.unwrap_aes_key(tampered_key)

    def test_unwrap_with_wrong_server_private_key_fails(self) -> None:
        """Verify ciphertext encrypted for Server A cannot be unwrapped by Server B."""
        server_a = RSAKeyExchangeServer()
        server_b = RSAKeyExchangeServer()

        client = RSAKeyExchangeClient(server_a.public_key)
        _, wrapped_key = client.generate_and_wrap_key(key_size=16)

        with pytest.raises(ValueError, match="Failed to unwrap AES key"):
            server_b.unwrap_aes_key(wrapped_key)

    def test_unwrap_enforces_expected_key_sizes(self) -> None:
        """Verify server rejects decrypted keys not matching allowed length constraints."""
        server = RSAKeyExchangeServer()
        client = RSAKeyExchangeClient(server.public_key)

        raw_key, wrapped = client.generate_and_wrap_key(key_size=16)

        # If server only expects 32-byte key (AES-256), 16-byte must fail validation
        with pytest.raises(ValueError, match="is not in expected sizes"):
            server.unwrap_aes_key(wrapped, expected_key_sizes=(32,))
