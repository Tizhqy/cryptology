"""PSEUDOCODE: Manuel AES-128 tek blok deneyi."""


def encrypt_block(block_16_bytes, key_16_bytes):
    # AES-128 hem anahtar hem de block icin 16 byte kullanir.
    state = xor_bytes(block_16_bytes, key_16_bytes)
    round_keys = expand_key(key_16_bytes)

    for round_number in range(1, 10):
        # SubBytes: her byte'i S-box ile non-linear degistir.
        state = sub_bytes(state)
        # ShiftRows: state satirlarini farkli miktarlarda kaydir.
        state = shift_rows(state)
        # MixColumns: her sutundaki byte'lari GF(2^8) icinde karistir.
        state = mix_columns(state)
        # AddRoundKey: round anahtarini XOR ile ekle.
        state = xor_bytes(state, round_keys[round_number])

    # Son round'da MixColumns uygulanmaz.
    state = sub_bytes(state)
    state = shift_rows(state)
    state = xor_bytes(state, round_keys[10])
    return state


def compare_with_library(block, key):
    manual_result = encrypt_block(block, key)
    library_result = library_aes_ecb_single_block(block, key)
    # Iki sonuc ayni olmali; fark varsa round veya key expansion hatasini ara.
    assert manual_result == library_result
    return manual_result
