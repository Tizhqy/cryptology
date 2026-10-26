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

