import importlib.util
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

ADAPTER_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "clients"
    / "client-app"
    / "infrastructure"
    / "cryptography"
    / "aes_gcm.py"
)
ADAPTER_SPEC = importlib.util.spec_from_file_location("client_aes_gcm", ADAPTER_PATH)
assert ADAPTER_SPEC is not None and ADAPTER_SPEC.loader is not None
ADAPTER_MODULE = importlib.util.module_from_spec(ADAPTER_SPEC)
ADAPTER_SPEC.loader.exec_module(ADAPTER_MODULE)

AES_KEY_SIZE_BYTES = ADAPTER_MODULE.AES_KEY_SIZE_BYTES
NONCE_SIZE_BYTES = ADAPTER_MODULE.NONCE_SIZE_BYTES
AesGcmAdapter = ADAPTER_MODULE.AesGcmAdapter


@pytest.fixture
def adapter():
    return AesGcmAdapter()


def test_encrypt_returns_nonce_and_authenticated_ciphertext(adapter):
    key = bytes(range(AES_KEY_SIZE_BYTES))
    plaintext = b"Merhaba, AES-GCM"

    nonce, ciphertext_and_tag = adapter.encrypt(key, plaintext)

    assert len(nonce) == NONCE_SIZE_BYTES
    assert len(ciphertext_and_tag) == len(plaintext) + 16
    assert ciphertext_and_tag != plaintext


@pytest.mark.parametrize("plaintext", [b"", b"short text", bytes(range(256))])
def test_encrypt_decrypt_round_trip(adapter, plaintext):
    key = bytes(range(AES_KEY_SIZE_BYTES))
    associated_data = b"message-type:text"

    nonce, ciphertext_and_tag = adapter.encrypt(key, plaintext, associated_data)

    assert adapter.decrypt(key, nonce, ciphertext_and_tag, associated_data) == plaintext


def test_encrypt_generates_a_new_nonce_for_each_payload(adapter):
    key = bytes(range(AES_KEY_SIZE_BYTES))

    first_nonce, _ = adapter.encrypt(key, b"first")
    second_nonce, _ = adapter.encrypt(key, b"second")

    assert first_nonce != second_nonce


def test_decrypt_rejects_modified_ciphertext(adapter):
    key = bytes(range(AES_KEY_SIZE_BYTES))
    nonce, ciphertext_and_tag = adapter.encrypt(key, b"authenticated message")
    modified = bytes([ciphertext_and_tag[0] ^ 1]) + ciphertext_and_tag[1:]

    with pytest.raises(InvalidTag):
        adapter.decrypt(key, nonce, modified)


def test_decrypt_rejects_wrong_associated_data(adapter):
    key = bytes(range(AES_KEY_SIZE_BYTES))
    nonce, ciphertext_and_tag = adapter.encrypt(key, b"message", b"header-a")

    with pytest.raises(InvalidTag):
        adapter.decrypt(key, nonce, ciphertext_and_tag, b"header-b")


@pytest.mark.parametrize("key", [b"", bytes(15), bytes(24), bytes(32)])
def test_encrypt_rejects_non_aes_128_keys(adapter, key):
    with pytest.raises(ValueError, match="AES-128 key must be exactly 16 bytes"):
        adapter.encrypt(key, b"message")


def test_decrypt_rejects_non_aes_128_keys(adapter):
    with pytest.raises(ValueError, match="AES-128 key must be exactly 16 bytes"):
        adapter.decrypt(bytes(15), bytes(NONCE_SIZE_BYTES), b"ciphertext")


@pytest.mark.parametrize("nonce", [b"", bytes(11), bytes(13)])
def test_decrypt_rejects_nonce_with_wrong_length(adapter, nonce):
    with pytest.raises(ValueError, match="AES-GCM nonce must be exactly 12 bytes"):
        adapter.decrypt(bytes(AES_KEY_SIZE_BYTES), nonce, b"ciphertext")