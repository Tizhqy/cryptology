from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time

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
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]    #ornegin baytin degeri 53 iste sbox da 5.satir  3. sutun
            
def shift_rows(state):
    state[0] = state[0]
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def mix_columns(state):
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

def add_round_key(state, round_key_matrix):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key_matrix[r][c]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key_bytes):
    w = [list(key_bytes[i:i+4]) for i in range(0, 16, 4)]     # 4 er baytlik 4 kelimeye boluyoz
    
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  #sola kaydir
            temp = [S_BOX[b] for b in temp] #sboxa sok
            temp[0] ^= RCON[i // 4]

        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    
    round_keys = []         # 44 kelimeyi 11 adet 4x4 sütun matrisine çevir
    for r in range(11):
        round_words = w[r*4:(r+1)*4]            # 4 sütun kelimesi
        matrix = [[round_words[c][row] for c in range(4)] for row in range(4)]   # State formatına uygun: satır x sütun
        round_keys.append(matrix)
    return round_keys

def encrypt_block(block_16_bytes, key_16_bytes, mode=128):
    state = [
        list(block_16_bytes[0:16:4]),
        list(block_16_bytes[1:16:4]),
        list(block_16_bytes[2:16:4]),
        list(block_16_bytes[3:16:4]),
    ]
    #mod ekeleme oalcak 128 192 256 icin
    
    round_keys = key_expansion(key_16_bytes)
    add_round_key(state, round_keys[0])

    for round_num in range(1, 10):  #1-9
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])
        
    sub_bytes(state)    #son turda mixcolumns yok
    shift_rows(state)
    add_round_key(state, round_keys[10])
    
    output = bytearray(16)      # State matrisini tekrar düz 16 bayta çevir (sütun öncelikli)
    idx = 0
    for c in range(4):
        for r in range(4):
            output[idx] = state[r][c]
            idx += 1
            
    return bytes(output)

def library_aes_encrypt(block_16_bytes, key_16_bytes):
    cipher = Cipher(algorithms.AES(key_16_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block_16_bytes) + encryptor.finalize()

def compare_with_library(block, key):
    manual_result = encrypt_block(block, key)
    library_result = library_aes_encrypt(block, key)
    
    print("Manuel Sonuc :", manual_result.hex())
    print("Kutuphane    :", library_result.hex())
    
    assert manual_result == library_result, "HATA: Sonuclar uyusmuyor!"
    print("BASARILI: Kendi implementasyonun kütüphaneyle birebir ayni calisiyor.")
    

plain_block = bytes.fromhex("00112233445566778899aabbccddeeff")
secret_key  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
expected    = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

print("=== 1. DOĞRULUK TESTİ ===")
my_cipher = encrypt_block(plain_block, secret_key)
lib_cipher = library_aes_encrypt(plain_block, secret_key)

print(f"Girdi (Plaintext) : {plain_block.hex()}")
print(f"Anahtar (Key)     : {secret_key.hex()}")
print("-" * 50)
print(f"Manuel AES Çıktı  : {my_cipher.hex()}")
print(f"Kütüphane Çıktı   : {lib_cipher.hex()}")
print(f"NIST Beklenen     : {expected.hex()}")

# Karşılaştırma doğrulaması
assert my_cipher == lib_cipher, "HATA: Kod kütüphane ile uyuşmuyor!"
assert my_cipher == expected, "HATA: Kod NIST standardı ile uyuşmuyor!"
print("\n[✓] TEST BAŞARILI: Manuel AES kütüphane ve NIST standardı ile birebir aynı üretti.\n")

# -------------------------------------------------------------------------
# 4. HIZ (PERFORMANS / BENCHMARK) KARŞILAŞTIRMASI
# -------------------------------------------------------------------------
print("=== 2. HIZ KARŞILAŞTIRMASI (10.000 Blok Şifreleme) ===")
ITERATIONS = 10_000

# Manuel AES Süresi
start = time.perf_counter()
for _ in range(ITERATIONS):
    encrypt_block(plain_block, secret_key)
manual_duration = time.perf_counter() - start

# Kütüphane Süresi (Cipher nesnesini loop dışında tutarak sadece şifreleme süresi ölçülür)
cipher = Cipher(algorithms.AES(secret_key), modes.ECB(), backend=default_backend())
start = time.perf_counter()
for _ in range(ITERATIONS):
    encryptor = cipher.encryptor()
    _ = encryptor.update(plain_block) + encryptor.finalize()
lib_duration = time.perf_counter() - start

# Hız Sonuçları
print(f"Manuel AES (Saf Python) : {manual_duration:.4f} saniye")
print(f"Kütüphane (C / AES-NI)  : {lib_duration:.4f} saniye")
print(f"Fark                    : Kütüphane yaklaşık {manual_duration / lib_duration:.1f} kat daha hızlı.")

# def encrypt_block(block_16_bytes, key_16_bytes):
#     # AES-128 hem anahtar hem de block icin 16 byte kullanir.
#     state = xor_bytes(block_16_bytes, key_16_bytes)
#     round_keys = expand_key(key_16_bytes)

#     for round_number in range(1, 10):
#         # SubBytes: her byte'i S-box ile non-linear degistir.
#         state = sub_bytes(state)
#         # ShiftRows: state satirlarini farkli miktarlarda kaydir.
#         state = shift_rows(state)
#         # MixColumns: her sutundaki byte'lari GF(2^8) icinde karistir.
#         state = mix_columns(state)
#         # AddRoundKey: round anahtarini XOR ile ekle.
#         state = xor_bytes(state, round_keys[round_number])

#     # Son round'da MixColumns uygulanmaz.
#     state = sub_bytes(state)
#     state = shift_rows(state)
#     state = xor_bytes(state, round_keys[10])
#     return state


# def compare_with_library(block, key):
#     manual_result = encrypt_block(block, key)
#     library_result = library_aes_ecb_single_block(block, key)
#     # Iki sonuc ayni olmali; fark varsa round veya key expansion hatasini ara.
#     assert manual_result == library_result
#     return manual_result