"""PSEUDOCODE: Manuel AES-128 tek blok deneyi."""




def encrypt_block(block_16_bytes, key_16_bytes):
    state = [
        list(block_16_bytes[0:16:4]),  # [b0, b4, b8, b12]
        list(block_16_bytes[1:16:4]),  # [b1, b5, b9, b13]
        list(block_16_bytes[2:16:4]),  # [b2, b6, b10, b14]
        list(block_16_bytes[3:16:4]),  # [b3, b7, b11, b15]
    ]
    
    words = [key_16_bytes[i:i+4] for i in range(0, len(key_16_bytes), 4)]
    
    temp=[]

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