"""PSEUDOCODE: PDF parcalarini relay etme akisinin taslagi.

This file is a design sketch, not executable application code.
"""

# pyright: reportUndefinedVariable=false


class RelayPdf:
    def execute(self, file_start_frame, chunk_frames):
        # Config'teki max_file_size_bytes sinirini ilk metadata'da kontrol et.
        require(file_start_frame.file_size <= settings.transfer.max_file_size_bytes)
        require(file_start_frame.extension == ".pdf")

        temporary_file = create_temp_file(file_start_frame.file_id)

        for frame in ordered_by_sequence(chunk_frames):
            plaintext_chunk = decrypt_from_sender(frame)
            write_chunk(temporary_file, plaintext_chunk)
            relay_encrypted_chunk_to_receiver(plaintext_chunk, frame)

        # Butun parcalar birlestikten sonra hash ile dosya butunlugunu kontrol et.
        actual_hash = sha256(temporary_file)
        require(actual_hash == file_start_frame.expected_sha256)
        send_file_complete_ack()
