"""
=============================================================================
Karadeniz Teknik Üniversitesi - Of Teknoloji Fakültesi
Yazılım Mühendisliği Bölümü - Güvenli Haberleşme Projesi
-----------------------------------------------------------------------------
Kütüphanesiz Manuel AES-128 Uygulaması (FIPS-197 Uyumlu)
Yazar: Yusuf Tan DURMUŞ (Öğrenci No: 445841)
-----------------------------------------------------------------------------
Bu modül, AES-128 (Advanced Encryption Standard - Rijndael) algoritmasını
herhangi bir kripto kütüphanesi kullanmadan, tamamen saf Python ile
matematiksel temelleri (GF(2^8) Galois Field aritmetiği, S-box dönüşümü,
ShiftRows, MixColumns ve Anahtar Genişletme) üzerinde adım adım uygular.

İçerik:
  1. GF(2^8) Galois Field Sonlu Cisim Aritmetiği & İndirgenemez Polinom
  2. Rijndael S-Box ve Ters S-Box (InvS-Box)
  3. Anahtar Genişletme (Key Expansion & Rcon)
  4. Temel Round Dönüşümleri (SubBytes, ShiftRows, MixColumns, AddRoundKey)
  5. Ters Round Dönüşümleri (InvSubBytes, InvShiftRows, InvMixColumns)
  6. Tek Blok (16-byte) Şifreleme ve Deşifreleme
  7. PKCS#7 Dolgulama (Padding & Unpadding)
  8. Çalışma Modları: ECB ve CBC (IV Destekli)
  9. NIST FIPS-197 Standart Test Vektörleri Doğrulaması
 10. Kütüphane (cryptography) Karşılaştırması ve Performans Benchmark'ı
=============================================================================
"""

from __future__ import annotations
import os
import sys
import time
from typing import List, Tuple

# Windows konsolunda Türkçe karakterlerin sorunsuz yazdırılması için
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 1. RIJNDAEL S-BOX VE TERS S-BOX TABLOLARI
# ---------------------------------------------------------------------------
# S-Box: GF(2^8) üzerinde çarpımsal ters alma ve ardından bir afin (affine)
# dönüşüm uygulanarak elde edilen 16x16'lık (256 elemanlı) ikame tablosudur.
# Non-linear (doğrusal olmayan) karışıklık (confusion) sağlar.

S_BOX: List[int] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# INV_S_BOX: Deşifreleme (Decryption) işleminde SubBytes'ın tersi olarak kullanılır.
# INV_S_BOX[S_BOX[x]] == x eşitliği sağlanır.
INV_S_BOX: List[int] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# RCON: KeyExpansion (Anahtar Genişletme) işleminde her 4 kelimede bir (i % 4 == 0)
# kullanılan round sabitleridir. Rcon[i] = [rc[i], 0x00, 0x00, 0x00] şeklindedir.
# rc[i] değeri GF(2^8) içinde x^(i-1) kuvvetidir.
RCON: List[int] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------------------------------------------------------------------------
# 2. GF(2^8) GALOIS FIELD ARİTMETİĞİ
# ---------------------------------------------------------------------------
def xtime(a: int) -> int:
    """
    GF(2^8) üzerinde bir baytın 'x' (yani 0x02) ile çarpımı.
    İndirgenemez (irreducible) polinom: m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
    Eğer en yüksek bit (0x80) 1 ise sola 1 kaydırılıp 0x1B ile XOR'lanır.
    """
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return (a << 1) & 0xFF


def gf_mul(a: int, b: int) -> int:
    """
    GF(2^8) Galois cismi üzerinde iki baytın genel çarpımı.
    AES MixColumns ve InvMixColumns işlemlerinde teorik doğrulamayı sağlar.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p


# ---------------------------------------------------------------------------
# 3. AES MATRİS (STATE) VE YARDIMCI DÖNÜŞÜMLERİ
# ---------------------------------------------------------------------------
# AES standardında (FIPS-197), 16 baytlık blok 4x4'lük bir 'State' matrisine
# SÜTUN ÖNCELİKLİ (Column-major) olarak yerleştirilir:
#   [ s0  s4  s8  s12 ]
#   [ s1  s5  s9  s13 ]
#   [ s2  s6  s10 s14 ]
#   [ s3  s7  s11 s15 ]

def bytes_to_state(data: bytes) -> List[List[int]]:
    """16 baytlık düz veriyi 4x4 State matrisine (satır x sütun) çevirir."""
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = data[c * 4 + r]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    """4x4 State matrisini sütun öncelikli okuyarak 16 baytlık diziye çevirir."""
    out = bytearray(16)
    idx = 0
    for c in range(4):
        for r in range(4):
            out[idx] = state[r][c]
            idx += 1
    return bytes(out)


def format_state_hex(state: List[List[int]]) -> str:
    """Rapor ve hata ayıklama için State matrisini 4 satırlık hex formatta basar."""
    lines = []
    for r in range(4):
        lines.append(" ".join(f"{state[r][c]:02x}" for c in range(4)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. TEMEL ROUND İŞLEMLERİ (ŞİFRELEME)
# ---------------------------------------------------------------------------
def sub_bytes(state: List[List[int]]) -> None:
    """
    State matrisindeki her bir baytı Rijndael S-Box değerine dönüştürür.
    Non-linear substitüsyon adımıdır (Karışıklık / Confusion).
    """
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    """
    State matrisinin satırlarını dairesel olarak sola kaydırır (Permütasyon / Diffusion).
      0. satır: 0 bayt kayar (değişmez)
      1. satır: 1 bayt sola kayar
      2. satır: 2 bayt sola kayar
      3. satır: 3 bayt sola kayar
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def mix_columns(state: List[List[int]]) -> None:
    """
    Her sütunu GF(2^8) üzerinde sabit bir polinom c(x) = {03}x^3 + {01}x^2 + {01}x + {02}
    ile çarpar. Matrisel gösterimi:
      [ 02  03  01  01 ]   [ s0 ]
      [ 01  02  03  01 ] * [ s1 ]
      [ 01  01  02  03 ]   [ s2 ]
      [ 03  01  01  02 ]   [ s3 ]
    xtime() fonksiyonu kullanılarak yüksek performansla bit düzeyinde hesaplanır.
    """
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)


def add_round_key(state: List[List[int]], round_key_matrix: List[List[int]]) -> None:
    """
    State matrisi ile o round'un 4x4'lük anahtar matrisini bit düzeyinde XOR'lar.
    """
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key_matrix[r][c]


# ---------------------------------------------------------------------------
# 5. TERS ROUND İŞLEMLERİ (DEŞİFRELEME)
# ---------------------------------------------------------------------------
def inv_sub_bytes(state: List[List[int]]) -> None:
    """State matrisindeki her baytı INV_S_BOX tablosu ile tersine dönüştürür."""
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def inv_shift_rows(state: List[List[int]]) -> None:
    """
    State matrisinin satırlarını dairesel olarak sağa kaydırır.
      0. satır: değişmez
      1. satır: 1 bayt sağa kayar (3 bayt sola ile aynı)
      2. satır: 2 bayt sağa kayar
      3. satır: 3 bayt sağa kayar (1 bayt sola ile aynı)
    """
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]


def inv_mix_columns(state: List[List[int]]) -> None:
    """
    Deşifrelemede MixColumns'ın tersi olan sabit matrisle sütun çarpımıdır:
      [ 0e  0b  0d  09 ]   [ s0 ]
      [ 09  0e  0b  0d ] * [ s1 ]
      [ 0d  09  0e  0b ]   [ s2 ]
      [ 0b  0d  09  0e ]   [ s3 ]
    0x0e, 0x0b, 0x0d ve 0x09 katsayıları xtime ardışıklığıyla bit düzeyinde hesaplanır:
      x2 = xtime(a)
      x4 = xtime(x2)
      x8 = xtime(x4)
      9*a  = x8 ^ a
      11*a = x8 ^ x2 ^ a
      13*a = x8 ^ x4 ^ a
      14*a = x8 ^ x4 ^ x2
    """
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]

        # Her baytın x2, x4, x8 katlarını önceden çıkaralım
        def mul_decomp(a: int) -> Tuple[int, int, int, int]:
            x2 = xtime(a)
            x4 = xtime(x2)
            x8 = xtime(x4)
            # 9, 11, 13, 14
            return (x8 ^ a), (x8 ^ x2 ^ a), (x8 ^ x4 ^ a), (x8 ^ x4 ^ x2)

        m9_0, m11_0, m13_0, m14_0 = mul_decomp(s0)
        m9_1, m11_1, m13_1, m14_1 = mul_decomp(s1)
        m9_2, m11_2, m13_2, m14_2 = mul_decomp(s2)
        m9_3, m11_3, m13_3, m14_3 = mul_decomp(s3)

        state[0][c] = m14_0 ^ m11_1 ^ m13_2 ^ m9_3
        state[1][c] = m9_0 ^ m14_1 ^ m11_2 ^ m13_3
        state[2][c] = m13_0 ^ m9_1 ^ m14_2 ^ m11_3
        state[3][c] = m11_0 ^ m13_1 ^ m9_2 ^ m14_3


# ---------------------------------------------------------------------------
# 6. ANAHTAR GENİŞLETME (KEY EXPANSION)
# ---------------------------------------------------------------------------
def rot_word(word: List[int]) -> List[int]:
    """4 baytlık kelimeyi sola 1 bayt kaydırır: [b0, b1, b2, b3] -> [b1, b2, b3, b0]."""
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    """4 baytlık kelimenin her baytını S_BOX ile ikame eder."""
    return [S_BOX[b] for b in word]


def key_expansion(key_16_bytes: bytes) -> List[List[List[int]]]:
    """
    AES-128 için 16 baytlık anahtardan 11 adet 4x4'lük Round Key matrisi üretir.
    Toplam 44 adet 4-baytlık kelime (w[0]..w[43]) üretilir:
      - İlk 4 kelime doğrudan anahtarın kendisidir.
      - Sonraki kelimeler: i % 4 == 0 ise SubWord(RotWord(w[i-1])) ^ Rcon[i/4] XOR w[i-4].
    """
    if len(key_16_bytes) != 16:
        raise ValueError(f"AES-128 anahtarı tam 16 bayt olmalıdır! Alınan: {len(key_16_bytes)} bayt")

    w: List[List[int]] = [list(key_16_bytes[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i // 4]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    # 44 kelimeyi 11 adet (Round 0 .. Round 10) 4x4 matrise yerleştirelim
    round_keys: List[List[List[int]]] = []
    for r in range(11):
        round_words = w[r * 4:(r + 1) * 4]  # 4 kelime (her biri bir sütun)
        # State matris formatına uygun olarak: matrix[row][col]
        matrix = [[round_words[c][row] for c in range(4)] for row in range(4)]
        round_keys.append(matrix)

    return round_keys


# ---------------------------------------------------------------------------
# 7. TEK BLOK (16-BYTE) ŞİFRELEME VE DEŞİFRELEME
# ---------------------------------------------------------------------------
def encrypt_block(block_16_bytes: bytes, key_16_bytes: bytes, verbose: bool = False) -> bytes:
    """
    AES-128 tek 16 baytlık blok şifrelemesi.
    Akış:
      - Ön Tur (Round 0): AddRoundKey
      - Turlar 1-9: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
      - Son Tur (Round 10): SubBytes -> ShiftRows -> AddRoundKey (MixColumns YOK!)
    """
    if len(block_16_bytes) != 16:
        raise ValueError(f"Blok boyutu 16 bayt olmalıdır! Alınan: {len(block_16_bytes)}")

    state = bytes_to_state(block_16_bytes)
    round_keys = key_expansion(key_16_bytes)

    if verbose:
        print(f"--- [ROUND 0] Başlangıç State ---\n{format_state_hex(state)}")

    # Round 0: Giriş Beyazlatma (Pre-whitening)
    add_round_key(state, round_keys[0])

    # Round 1 - 9: Standart Turlar
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
        if verbose and (r == 1 or r == 9):
            print(f"--- [ROUND {r}] Çıkış State ---\n{format_state_hex(state)}")

    # Round 10: Son Tur (MixColumns uygulanmaz!)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    if verbose:
        print(f"--- [ROUND 10 - FINAL] Son State ---\n{format_state_hex(state)}")

    return state_to_bytes(state)


def decrypt_block(ciphertext_16_bytes: bytes, key_16_bytes: bytes, verbose: bool = False) -> bytes:
    """
    AES-128 tek 16 baytlık blok deşifrelemesi (Ters Şifre).
    Akış (Ters Sıra):
      - Başlangıç: AddRoundKey(Round 10 Key)
      - Turlar 9-1: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
      - Son Adım (Round 0 Key): InvShiftRows -> InvSubBytes -> AddRoundKey(Round 0 Key)
    """
    if len(ciphertext_16_bytes) != 16:
        raise ValueError(f"Şifreli blok boyutu 16 bayt olmalıdır! Alınan: {len(ciphertext_16_bytes)}")

    state = bytes_to_state(ciphertext_16_bytes)
    round_keys = key_expansion(key_16_bytes)

    # Başlangıç: Son turun anahtarı eklenir
    add_round_key(state, round_keys[10])

    # Tur 9'dan 1'e doğru geri sarılır
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
        if verbose and (r == 9 or r == 1):
            print(f"--- [INV ROUND {r}] Çıkış State ---\n{format_state_hex(state)}")

    # Tur 0 (Final): InvMixColumns uygulanmaz
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ---------------------------------------------------------------------------
# 8. PKCS#7 DOLGULAMA (PADDING & UNPADDING)
# ---------------------------------------------------------------------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    PKCS#7 standardına göre veriyi blok boyutunun (16 bayt) katı yapar.
    Eğer veri zaten 16'nın katıysa, deşifrelemede belirsizliği önlemek için
    tam bir blok (16 adet 0x10) dolgu eklenir.
    """
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    PKCS#7 dolgusunu doğrular ve temizler.
    Hatalı dolgu baytları tespit edilirse ValueError fırlatır (Padding Oracle koruması).
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Geçersiz veri boyutu: Blok boyutu 16'nın katı olmalıdır!")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"Geçersiz PKCS#7 dolgu boyutu: {pad_len}")

    # Son pad_len baytın tamamı pad_len değerinde olmalıdır
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Bozuk PKCS#7 dolgusu tespit edildi!")

    return data[:-pad_len]


# ---------------------------------------------------------------------------
# 9. ÇALIŞMA MODLARI: ECB VE CBC (IV DESTEKLİ)
# ---------------------------------------------------------------------------
def encrypt_ecb(plaintext: bytes, key: bytes, pad: bool = True) -> bytes:
    """
    ECB (Electronic Codebook) Modu:
    Her blok birbirinden bağımsız şifrelenir.
    NOT: Aynı düz metin blokları aynı şifreli blokları üretir (desen sızdırır).
    """
    data = pkcs7_pad(plaintext) if pad else plaintext
    if len(data) % 16 != 0:
        raise ValueError("Veri boyutu 16'nın katı olmalıdır (veya pad=True verilmeli).")

    ciphertext = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        ciphertext.extend(encrypt_block(block, key))
    return bytes(ciphertext)


def decrypt_ecb(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    """ECB Modu Deşifreleme."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("Şifreli metin boyutu 16'nın katı olmalıdır.")

    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext.extend(decrypt_block(block, key))

    return pkcs7_unpad(bytes(plaintext)) if unpad else bytes(plaintext)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    """
    CBC (Cipher Block Chaining) Modu:
    Her düz metin bloğu şifrelenmeden önce bir önceki şifreli blokla (ilk blok ise IV ile) XOR'lanır:
      C_0 = Encrypt(P_0 ^ IV)
      C_i = Encrypt(P_i ^ C_{i-1})
    Bu sayede aynı düz metinler her seferinde tamamen farklı şifreli metinler üretir.
    """
    if len(iv) != 16:
        raise ValueError(f"CBC modu için IV tam 16 bayt olmalıdır! Alınan: {len(iv)}")

    data = pkcs7_pad(plaintext) if pad else plaintext
    ciphertext = bytearray()
    prev_block = iv

    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        # P_i ^ prev_block
        xored = bytes(b ^ p for b, p in zip(block, prev_block))
        enc_block = encrypt_block(xored, key)
        ciphertext.extend(enc_block)
        prev_block = enc_block

    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    """
    CBC Modu Deşifreleme:
      P_0 = Decrypt(C_0) ^ IV
      P_i = Decrypt(C_i) ^ C_{i-1}
    """
    if len(iv) != 16:
        raise ValueError(f"CBC modu için IV tam 16 bayt olmalıdır! Alınan: {len(iv)}")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Şifreli metin boyutu 16'nın katı olmalıdır.")

    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec_block = decrypt_block(block, key)
        # Decrypt(C_i) ^ prev_block
        pt_block = bytes(d ^ p for d, p in zip(dec_block, prev_block))
        plaintext.extend(pt_block)
        prev_block = block

    return pkcs7_unpad(bytes(plaintext)) if unpad else bytes(plaintext)


# ---------------------------------------------------------------------------
# 10. NESNE YÖNELİMLİ SARMALAYICI SINIF (ManualAES128)
# ---------------------------------------------------------------------------
class ManualAES128:
    """
    Yusuf Tan Durmuş tarafından yazılmış saf Python AES-128 sınıfı.
    Tek blok, ECB ve CBC modlarını kolay ve güvenli bir arayüzle sunar.
    """

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError(f"AES-128 anahtarı tam 16 bayt (128 bit) olmalıdır. Alınan: {len(key)}")
        self.key = key

    def encrypt_block(self, block: bytes, verbose: bool = False) -> bytes:
        return encrypt_block(block, self.key, verbose=verbose)

    def decrypt_block(self, block: bytes, verbose: bool = False) -> bytes:
        return decrypt_block(block, self.key, verbose=verbose)

    def encrypt(self, data: bytes, mode: str = "CBC", iv: bytes | None = None) -> Tuple[bytes, bytes | None]:
        """
        Metin veya dosyayı şifreler.
        CBC modunda IV verilmezse rastgele 16 baytlık güvenli IV üretilir.
        Döndürür: (ciphertext, iv)
        """
        mode = mode.upper()
        if mode == "ECB":
            return encrypt_ecb(data, self.key, pad=True), None
        elif mode == "CBC":
            if iv is None:
                iv = os.urandom(16)
            return encrypt_cbc(data, self.key, iv, pad=True), iv
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode}. 'ECB' veya 'CBC' seçiniz.")

    def decrypt(self, ciphertext: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
        """Şifreli metni çözer."""
        mode = mode.upper()
        if mode == "ECB":
            return decrypt_ecb(ciphertext, self.key, unpad=True)
        elif mode == "CBC":
            if iv is None:
                raise ValueError("CBC modu deşifrelemesi için IV zorunludur!")
            return decrypt_cbc(ciphertext, self.key, iv, unpad=True)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode}. 'ECB' veya 'CBC' seçiniz.")


# ---------------------------------------------------------------------------
# 11. NIST FIPS-197 VE KÜTÜPHANELİ KARŞILAŞTIRMA TESTLERİ
# ---------------------------------------------------------------------------
def run_nist_fips197_tests() -> bool:
    """
    NIST FIPS-197 resmi test vektörleri ile tek blok şifreleme ve deşifreleme doğrulaması.
    """
    print("\n" + "=" * 70)
    print("1. NIST FIPS-197 RESMİ TEST VEKTÖRLERİ DOĞRULAMASI")
    print("=" * 70)

    # Test Vektörü 1 (FIPS-197 Ek B)
    key_b = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt_b = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct_b = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    ct_b = encrypt_block(pt_b, key_b)
    dec_b = decrypt_block(ct_b, key_b)

    print(f"[Vektör 1 - Ek B] Düz Metin : {pt_b.hex()}")
    print(f"[Vektör 1 - Ek B] Anahtar    : {key_b.hex()}")
    print(f"[Vektör 1 - Ek B] Manuel CT  : {ct_b.hex()}")
    print(f"[Vektör 1 - Ek B] Beklenen   : {expected_ct_b.hex()}")
    assert ct_b == expected_ct_b, "HATA: Vektör 1 şifrelemesi başarısız!"
    assert dec_b == pt_b, "HATA: Vektör 1 deşifrelemesi başarısız!"
    print("  -> [BAŞARILI] Vektör 1 şifreleme ve deşifreleme NIST ile %100 eşleşti.")

    # Test Vektörü 2 (FIPS-197 Ek C.1)
    key_c = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt_c = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct_c = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    ct_c = encrypt_block(pt_c, key_c)
    dec_c = decrypt_block(ct_c, key_c)

    print(f"\n[Vektör 2 - Ek C.1] Düz Metin : {pt_c.hex()}")
    print(f"[Vektör 2 - Ek C.1] Anahtar    : {key_c.hex()}")
    print(f"[Vektör 2 - Ek C.1] Manuel CT  : {ct_c.hex()}")
    print(f"[Vektör 2 - Ek C.1] Beklenen   : {expected_ct_c.hex()}")
    assert ct_c == expected_ct_c, "HATA: Vektör 2 şifrelemesi başarısız!"
    assert dec_c == pt_c, "HATA: Vektör 2 deşifrelemesi başarısız!"
    print("  -> [BAŞARILI] Vektör 2 şifreleme ve deşifreleme NIST ile %100 eşleşti.")

    return True


def compare_with_cryptography_library() -> bool:
    """
    Manuel AES'i endüstri standardı 'cryptography' kütüphanesi ile karşılaştırır.
    ECB ve CBC modlarında hem şifreli çıktı hem de çözülen metin test edilir.
    """
    print("\n" + "=" * 70)
    print("2. KÜTÜPHANE (cryptography) İLE BİREBİR KARŞILAŞTIRMA TESTİ")
    print("=" * 70)

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("[UYARI] 'cryptography' paketi yüklü değil. 'pip install cryptography' yapabilirsiniz.")
        return False

    key = bytes.fromhex("a01b2c3d4e5f60718293a4b5c6d7e8f9")
    iv = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
    plaintext = "KTÜ Of Teknoloji Fakültesi Güvenli Haberleşme AES-128 Manuel Deneyi!".encode("utf-8")

    padded_plaintext = pkcs7_pad(plaintext)

    # --- ECB Modu Karşılaştırması ---
    manual_ecb = encrypt_ecb(plaintext, key, pad=True)
    cipher_lib_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc_lib_ecb = cipher_lib_ecb.encryptor()
    lib_ecb = enc_lib_ecb.update(padded_plaintext) + enc_lib_ecb.finalize()

    print("[ECB Modu]")
    print(f"  Manuel Çıktı  : {manual_ecb.hex()[:48]}... (uzunluk: {len(manual_ecb)} bayt)")
    print(f"  Kütüphane     : {lib_ecb.hex()[:48]}... (uzunluk: {len(lib_ecb)} bayt)")
    assert manual_ecb == lib_ecb, "HATA: ECB modu kütüphane çıktısıyla uyuşmuyor!"
    print("  -> [OK] ECB modu kütüphane ile BİREBİR AYNI.")

    # --- CBC Modu Karşılaştırması ---
    manual_cbc = encrypt_cbc(plaintext, key, iv, pad=True)
    cipher_lib_cbc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc_lib_cbc = cipher_lib_cbc.encryptor()
    lib_cbc = enc_lib_cbc.update(padded_plaintext) + enc_lib_cbc.finalize()

    print("\n[CBC Modu + IV]")
    print(f"  IV            : {iv.hex()}")
    print(f"  Manuel Çıktı  : {manual_cbc.hex()[:48]}... (uzunluk: {len(manual_cbc)} bayt)")
    print(f"  Kütüphane     : {lib_cbc.hex()[:48]}... (uzunluk: {len(lib_cbc)} bayt)")
    assert manual_cbc == lib_cbc, "HATA: CBC modu kütüphane çıktısıyla uyuşmuyor!"
    print("  -> [OK] CBC modu kütüphane ile BİREBİR AYNI.")

    # Deşifreleme doğrulaması
    dec_manual = decrypt_cbc(manual_cbc, key, iv, unpad=True)
    assert dec_manual == plaintext, "HATA: Manuel CBC deşifrelemesi asıl metni vermedi!"
    print(f"  -> [OK] Çözülen metin: '{dec_manual.decode('utf-8')}'")

    return True


def run_performance_benchmark(iterations: int = 2000) -> None:
    """
    Manuel AES (saf Python) ile Kütüphaneli AES (C / AES-NI donanım hızlandırma)
    arasındaki hız ve verimlilik farkını ölçer. Proje raporunun 5. maddesi için veri üretir.
    """
    print("\n" + "=" * 70)
    print(f"3. PERFORMANS / BENCHMARK ÖLÇÜMÜ ({iterations:,} Blok Şifreleme)")
    print("=" * 70)

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        has_lib = True
    except ImportError:
        has_lib = False

    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Manuel AES Ölçümü
    t0 = time.perf_counter()
    for _ in range(iterations):
        encrypt_block(block, key)
    t_manual = time.perf_counter() - t0

    print(f"Manuel AES (Saf Python)       : {t_manual:.4f} saniye")
    print(f"  -> Blok başına ortalama     : {(t_manual / iterations) * 1000:.4f} ms")
    bytes_total = iterations * 16
    print(f"  -> Veri Akış Hızı (Throughput): {(bytes_total / t_manual) / (1024 * 1024):.2f} MB/s")

    if has_lib:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        t0 = time.perf_counter()
        for _ in range(iterations):
            enc = cipher.encryptor()
            _ = enc.update(block) + enc.finalize()
        t_lib = time.perf_counter() - t0

        print(f"\nKütüphane AES (C / AES-NI)    : {t_lib:.4f} saniye")
        print(f"  -> Blok başına ortalama     : {(t_lib / iterations) * 1000:.4f} ms")
        print(f"  -> Veri Akış Hızı (Throughput): {(bytes_total / t_lib) / (1024 * 1024):.2f} MB/s")

        ratio = t_manual / t_lib if t_lib > 0 else 0
        print("-" * 70)
        print(f"SONUÇ: Kütüphane yaklaşık {ratio:.1f} kat daha hızlıdır.")
        print("RAPOR NOTU (Bölüm 5):")
        print("  1. Saf Python kodu yorumlayıcı (bytecode VM) üzerinde dinamik tip kontrolüyle çalışır.")
        print("  2. Kütüphaneli versiyon (OpenSSL / cryptography), modern işlemcilerin donanımsal")
        print("     AES talimat setini (AES-NI: aesenc, aesenclast) doğrudan assembly düzeyinde çalıştırır.")
        print("  3. Bu nedenle üretim güvenliğinde (production) kütüphaneli AES-128-GCM tercih edilir;")
        print("     manuel AES ise eğitim, algoritma adımlarını kavrama ve doğrulama amaçlıdır.")


# ---------------------------------------------------------------------------
# 12. ETKİLEŞİMLİ VE GÖRSEL ÇALIŞTIRMA
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("""
    #####################################################################
    #          KARADENİZ TEKNİK ÜNİVERSİTESİ - OF TEKNOLOJİ FAKÜLTESİ    #
    #          YAZILIM MÜHENDİSLİĞİ - GÜVENLİ HABERLEŞME PROJESİ         #
    #                 KÜTÜPHANESİZ MANUEL AES-128 MODÜLÜ                #
    #                 Geliştirici: Yusuf Tan DURMUŞ (445841)            #
    #####################################################################
    """)

    # 1. NIST Test Vektörleri
    run_nist_fips197_tests()

    # 2. Adım Adım Round İçi Durum (State) İncelemesi (Rapor için örnek çıktı)
    print("\n" + "=" * 70)
    print("ÖĞRETİCİ GÖSTERİM: TEK BLOK İÇİN ADIM ADIM ROUND STATE İNCELEMESİ")
    print("=" * 70)
    sample_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    sample_pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    encrypt_block(sample_pt, sample_key, verbose=True)

    # 3. Kütüphane Karşılaştırması
    compare_with_cryptography_library()

    # 4. Performans Ölçümü
    run_performance_benchmark(iterations=2000)

    print("\n[OK] TÜM MANUEL AES TESTLERİ VE DOĞRULAMALAR EKSİKSİZ TAMAMLANDI.")
