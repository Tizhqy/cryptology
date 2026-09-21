"""PSEUDOCODE: Client application use-case'leri."""


class SendText:
    def execute(self, text, receiver_id):
        # Secilen profile gore plaintext veya AES-GCM frame olustur.
        frame = message_builder.build_text_frame(text, receiver_id)
        transport.send(frame)
        return wait_for_ack(frame.message_id)


class SendPdf:
    def execute(self, pdf_path, receiver_id):
        # Uzanti, boyut ve config limitini kontrol et.
        file_info = pdf_chunker.inspect(pdf_path)
        require(file_info.extension == ".pdf")
        require(file_info.size <= settings.transfer.max_file_size_bytes)

        transport.send(build_file_start(file_info, receiver_id))
        for chunk in pdf_chunker.read_chunks(pdf_path, settings.transfer.chunk_size_bytes):
            transport.send(build_file_chunk(chunk, file_info, receiver_id))
        transport.send(build_file_complete(file_info, receiver_id))
        return wait_for_ack(file_info.file_id)


class EstablishSession:
    def execute(self):
        # Factory secilen RSA/DH/ECDH/ML-KEM provider'ini verir.
        provider = key_exchange_factory.create(settings.security.key_exchange)
        session_key = provider.establish_with_server(transport)
        session_store.save(session_key)
        return session_key
