"""
Tests for Manual AES-128 Implementation (Yusuf Tan Durmuş).
Validates FIPS-197 Known Answer Tests, padding, CBC mode, and library equivalence.
"""

import os
import pytest
from experiments.manual_aes.yusuf_aes import (
    ManualAES128,
    encrypt_block,
    decrypt_block,
    pkcs7_pad,
    pkcs7_unpad,
    encrypt_ecb,
    decrypt_ecb,
    encrypt_cbc,
    decrypt_cbc,
    gf_mul,
    xtime,
    S_BOX,
    INV_S_BOX,
)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class TestManualAESMathAndTables:
    def test_sbox_inversion(self):
        """Her byte için INV_S_BOX[S_BOX[b]] == b olmalıdır."""
        for b in range(256):
            assert INV_S_BOX[S_BOX[b]] == b

    def test_gf_mul_fips197_example(self):
        """FIPS 197 Bölüm 4.2: {57} * {83} = {c1} olmalıdır."""
        assert gf_mul(0x57, 0x83) == 0xC1

    def test_xtime_consistency(self):
        """xtime(a), gf_mul(a, 2) ile tam eşleşmelidir."""
        for a in range(256):
            assert xtime(a) == gf_mul(a, 0x02)


class TestNISTKnownAnswerVectors:
    def test_fips197_appendix_b_vector(self):
        """NIST FIPS-197 Ek B test vektörü."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        ct = encrypt_block(pt, key)
        assert ct == expected_ct
        assert decrypt_block(ct, key) == pt

    def test_fips197_appendix_c1_vector(self):
        """NIST FIPS-197 Ek C.1 test vektörü."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        ct = encrypt_block(pt, key)
        assert ct == expected_ct
        assert decrypt_block(ct, key) == pt


class TestPaddingAndModes:
    def test_pkcs7_padding_roundtrip(self):
        """Farklı uzunluktaki veriler için PKCS#7 pad/unpad testi."""
        for length in [0, 1, 15, 16, 17, 31, 32, 100]:
            data = os.urandom(length)
            padded = pkcs7_pad(data)
            assert len(padded) % 16 == 0
            assert pkcs7_unpad(padded) == data

    def test_pkcs7_invalid_padding_raises(self):
        """Bozuk dolguda hata fırlatmalıdır."""
        with pytest.raises(ValueError):
            pkcs7_unpad(b"0123456789abcdef\x00")  # geçersiz pad byte

        with pytest.raises(ValueError):
            pkcs7_unpad(b"0123456789abcde\x02")  # tutarsız pad bytes

    def test_ecb_roundtrip(self):
        key = os.urandom(16)
        message = b"Guvenli haberlesme dersi projesi - Yusuf Tan Durmus"
        ciphertext = encrypt_ecb(message, key, pad=True)
        decrypted = decrypt_ecb(ciphertext, key, unpad=True)
        assert decrypted == message

    def test_cbc_roundtrip(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        message = b"KTU Of Teknoloji Fakultesi Yazilim Muhendisligi AES-128 CBC"
        ciphertext = encrypt_cbc(message, key, iv, pad=True)
        decrypted = decrypt_cbc(ciphertext, key, iv, unpad=True)
        assert decrypted == message


class TestCryptographyLibraryEquivalence:
    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography kütüphanesi yüklü değil")
    def test_compare_ecb_with_library(self):
        key = os.urandom(16)
        data = b"Ders haftalarina karsilik bagimsiz deneyler ve manuel AES dogrulamasi!"
        padded_data = pkcs7_pad(data)

        # Manuel
        manual_ct = encrypt_ecb(data, key, pad=True)

        # Kütüphane
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        lib_ct = enc.update(padded_data) + enc.finalize()

        assert manual_ct == lib_ct

    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography kütüphanesi yüklü değil")
    def test_compare_cbc_with_library(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        data = b"%PDF-1.4 sample PDF header chunk data for safe encrypted relay!"
        padded_data = pkcs7_pad(data)

        # Manuel
        manual_ct = encrypt_cbc(data, key, iv, pad=True)

        # Kütüphane
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        lib_ct = enc.update(padded_data) + enc.finalize()

        assert manual_ct == lib_ct


class TestManualAES128ClassWrapper:
    def test_class_wrapper_cbc(self):
        key = os.urandom(16)
        aes = ManualAES128(key)
        data = b"Class wrapper CBC encryption test."
        ct, iv = aes.encrypt(data, mode="CBC")
        assert iv is not None
        assert len(iv) == 16
        pt = aes.decrypt(ct, mode="CBC", iv=iv)
        assert pt == data

    def test_class_wrapper_ecb(self):
        key = os.urandom(16)
        aes = ManualAES128(key)
        data = b"Class wrapper ECB encryption test."
        ct, iv = aes.encrypt(data, mode="ECB")
        assert iv is None
        pt = aes.decrypt(ct, mode="ECB")
        assert pt == data
