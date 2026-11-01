"""
AES blogu her zaman 16 bayttir; anahtar 16/24/32 bayt olabilir.
Akis: anahtar genisletme, baslangic AddRoundKey, normal turlar ve MixColumns'suz son tur.
Bu dosyadaki ECB kullanimi yalnizca tek blokluk kutuphane karsilastirmasi icindir.
"""

import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE_BYTES = 16
KEY_SIZE_BYTES = {128: 16, 192: 24, 256: 32}
KEY_SIZE_BITS_BY_BYTES = {byte_count: bit_count for bit_count, byte_count in KEY_SIZE_BYTES.items()}

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def sub_bytes(state):
    """State'teki her bayti S-Box tablosundaki dogrusal olmayan degeriyle degistirir."""
    for r in range(4):
        for c in range(4):
            # Ornek: S_BOX[0x53], tablonun 5. satir 3. sutunundaki 0xED degeridir.
            state[r][c] = S_BOX[state[r][c]]
            
def shift_rows(state):
    """State satirlarini sola 0, 1, 2 ve 3 bayt kaydirarak konumlari karistirir."""
    state[0] = state[0]
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    """GF(2^8) alaninda bir bayti 2 ile carpar; tasma varsa 0x1B ile indirger."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def mix_columns(state):
    """Her state sutununu AES sabit matrisiyle GF(2^8) icinde karistirir."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

def add_round_key(state, round_key_matrix):
    """State'in her baytini bu turun anahtarindaki karsiligiyla XOR'lar."""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key_matrix[r][c]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def _resolve_key_size(key_bytes, key_size_bits=None):
    """Anahtar bayt sayisindan AES boyutunu bulur ve istege bagli boyutu dogrular."""
    detected_size = KEY_SIZE_BITS_BY_BYTES.get(len(key_bytes))
    if detected_size is None:
        raise ValueError("AES key must be exactly 16, 24, or 32 bytes.")
    if key_size_bits is not None:
        if key_size_bits not in KEY_SIZE_BYTES:
            raise ValueError("AES key size must be 128, 192, or 256 bits.")
        if key_size_bits != detected_size:
            raise ValueError("AES key size does not match the key byte length.")
    return detected_size


def key_expansion(key_bytes):
    """Anahtardan Nr+1 round anahtari uretir; AES-256'nin ek SubWord adimini da uygular."""
    key_size_bits = _resolve_key_size(key_bytes)
    words_per_key = key_size_bits // 32  # Nk: anahtardaki 32 bitlik kelime sayısı.
    round_count = words_per_key + 6  # AES standardında Nr = Nk + 6.
    word_count = 4 * (round_count + 1)
    words = [list(key_bytes[i:i + 4]) for i in range(0, len(key_bytes), 4)]

    for i in range(words_per_key, word_count):
        temp = list(words[i - 1])
        if i % words_per_key == 0:
            # Her Nk kelimede RotWord, SubWord ve Rcon uygulanır.
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[byte] for byte in temp]
            temp[0] ^= RCON[i // words_per_key]
        elif words_per_key == 8 and i % words_per_key == 4:
            # AES-256'da her anahtar grubunun ortasında ek SubWord uygulanır.
            temp = [S_BOX[byte] for byte in temp]

        words.append([words[i - words_per_key][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for round_index in range(round_count + 1):
        round_words = words[round_index * 4:(round_index + 1) * 4]
        matrix = [[round_words[column][row] for column in range(4)] for row in range(4)]
        round_keys.append(matrix)
    return round_keys


def encrypt_block(block_16_bytes, key_bytes, key_size_bits=None):
    """Tek 16 baytlik blogu sifreler; padding yapmaz ve 16/24/32 bayt anahtar kabul eder."""
    if len(block_16_bytes) != BLOCK_SIZE_BYTES:
        raise ValueError("AES block must be exactly 16 bytes.")
    _resolve_key_size(key_bytes, key_size_bits)

    # 16 bayt, AES state matrisine sütun sütun yerleştirilir.
    state = [
        list(block_16_bytes[0::4]),
        list(block_16_bytes[1::4]),
        list(block_16_bytes[2::4]),
        list(block_16_bytes[3::4]),
    ]
    round_keys = key_expansion(key_bytes)
    add_round_key(state, round_keys[0])

    round_count = len(round_keys) - 1
    for round_num in range(1, round_count):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])

    # AES omits MixColumns in the final round.
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[round_count])

    output = bytearray(BLOCK_SIZE_BYTES)
    idx = 0
    for c in range(4):
        for r in range(4):
            output[idx] = state[r][c]
            idx += 1

    return bytes(output)


def library_aes_encrypt(block_16_bytes, key_bytes, key_size_bits=None):
    """Tek blokluk test icin cryptography kutuphanesiyle AES-ECB sifrelemesi yapar."""
    if len(block_16_bytes) != BLOCK_SIZE_BYTES:
        raise ValueError("AES block must be exactly 16 bytes.")
    _resolve_key_size(key_bytes, key_size_bits)
    # ECB yalnızca tek blokluk manuel AES karşılaştırması için kullanılır.
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block_16_bytes) + encryptor.finalize()


def compare_with_library(block, key, key_size_bits=None):
    """Manuel ve kutuphane sonuclarini yazdirip esit olduklarini kontrol eder."""
    manual_result = encrypt_block(block, key, key_size_bits)
    library_result = library_aes_encrypt(block, key, key_size_bits)

    print("Manuel Sonuc :", manual_result.hex())
    print("Kutuphane    :", library_result.hex())

    assert manual_result == library_result, "HATA: Sonuclar uyusmuyor!"
    print("BASARILI: Kendi implementasyonun kütüphaneyle birebir ayni calisiyor.")


TEST_VECTORS = (
    (128, "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (192, "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
)
TEST_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")


def main():
    """Uc NIST test vektorunu dogrular, sonra manuel/kutuphane hizini karsilastirir."""
    iterations = 10_000

    # Adim 1: Test vektorundaki hex metinleri gercek baytlara donusturulur.
    # Adim 2: encrypt_block, 16 bayti AES'in sutun-oncelikli 4x4 state'ine koyar.
    # Adim 3: key_expansion anahtardan round anahtarlarini uretir; ilk anahtar eklenir.
    # Adim 4: Her tur SubBytes, ShiftRows, MixColumns ve AddRoundKey uygular.
    # Adim 5: Son tur MixColumns'u atlar; sonuc NIST ve kutuphane ile karsilastirilir.
    for key_size_bits, key_hex, expected_hex in TEST_VECTORS:
        key = bytes.fromhex(key_hex)
        expected = bytes.fromhex(expected_hex)
        manual_result = encrypt_block(TEST_PLAINTEXT, key, key_size_bits)
        library_result = library_aes_encrypt(TEST_PLAINTEXT, key, key_size_bits)
        assert manual_result == expected
        assert library_result == expected
        print(f"AES-{key_size_bits} NIST vektoru: {manual_result.hex()} [OK]")

        start = time.perf_counter()
        for _ in range(iterations):
            encrypt_block(TEST_PLAINTEXT, key, key_size_bits)
        manual_duration = time.perf_counter() - start

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        start = time.perf_counter()
        for _ in range(iterations):
            encryptor = cipher.encryptor()
            encryptor.update(TEST_PLAINTEXT)
            encryptor.finalize()
        library_duration = time.perf_counter() - start
        print(
            f"  {iterations} blok: manuel {manual_duration:.4f}s, "
            f"kutuphane {library_duration:.4f}s"
        )


if __name__ == "__main__":
    main()