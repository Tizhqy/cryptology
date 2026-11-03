import pytest

from experiments.manual_aes.mehmet_aes import (
    TEST_PLAINTEXT,
    encrypt_block,
    key_expansion,
    library_aes_encrypt,
)


TEST_VECTORS = [
    (128, "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (192, "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
]


@pytest.mark.parametrize("key_size_bits,key_hex,ciphertext_hex", TEST_VECTORS)
def test_encrypt_block_matches_nist_vector(key_size_bits, key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    expected = bytes.fromhex(ciphertext_hex)

    assert encrypt_block(TEST_PLAINTEXT, key) == expected
    assert encrypt_block(TEST_PLAINTEXT, key, key_size_bits) == expected


@pytest.mark.parametrize("key_size_bits,key_hex,ciphertext_hex", TEST_VECTORS)
def test_encrypt_block_matches_cryptography_library(key_size_bits, key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)

    assert encrypt_block(TEST_PLAINTEXT, key, key_size_bits) == library_aes_encrypt(
        TEST_PLAINTEXT, key, key_size_bits
    )


@pytest.mark.parametrize("key_size_bits,key_hex,_", TEST_VECTORS)
def test_key_expansion_creates_expected_round_key_count(key_size_bits, key_hex, _):
    key = bytes.fromhex(key_hex)

    assert len(key_expansion(key)) == key_size_bits // 32 + 7


@pytest.mark.parametrize("block", [b"short", bytes(15), bytes(17)])
def test_encrypt_block_rejects_non_16_byte_blocks(block):
    with pytest.raises(ValueError, match="block must be exactly 16 bytes"):
        encrypt_block(block, bytes(16))


@pytest.mark.parametrize("key_length", [15, 20, 23, 25, 31, 33])
def test_encrypt_block_rejects_invalid_key_lengths(key_length):
    with pytest.raises(ValueError, match="key must be exactly 16, 24, or 32 bytes"):
        encrypt_block(TEST_PLAINTEXT, bytes(key_length))


def test_encrypt_block_rejects_mismatched_key_size_argument():
    with pytest.raises(ValueError, match="does not match the key byte length"):
        encrypt_block(TEST_PLAINTEXT, bytes(16), key_size_bits=192)


def test_encrypt_block_rejects_unsupported_key_size_argument():
    with pytest.raises(ValueError, match="must be 128, 192, or 256 bits"):
        encrypt_block(TEST_PLAINTEXT, bytes(16), key_size_bits=160)