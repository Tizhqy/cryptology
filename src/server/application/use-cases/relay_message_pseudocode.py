"""PSEUDOCODE: Server relay use-case."""


class RelayMessage:
    def __init__(self, client_registry, decryptor_factory, encryptor_factory, audit_sink):
        self.client_registry = client_registry
        self.decryptor_factory = decryptor_factory
        self.encryptor_factory = encryptor_factory
        self.audit_sink = audit_sink

    def execute(self, incoming_frame):
        # Gonderen ve hedef client kayitli mi kontrol et.
        sender = self.client_registry.require(incoming_frame.sender_id)
        receiver = self.client_registry.require(incoming_frame.receiver_id)

        # Insecure profilde payload plaintext'tir; secure profilde sender key ile acilir.
        plaintext = self.decryptor_factory.for_client(sender).decrypt(incoming_frame)

        # Odev geregi server plaintext'i ekrana basabilir; kalici log'a yazmaz.
        display_on_console(plaintext, message_id=incoming_frame.message_id)
        self.audit_sink.record("message_relayed", safe_metadata(incoming_frame))

        # Hedef client icin kendi AES session key'i ile yeniden sifrele.
        outgoing_frame = self.encryptor_factory.for_client(receiver).encrypt(
            plaintext,
            metadata=incoming_frame.metadata_for_receiver(),
        )
        receiver.send(outgoing_frame)
        return outgoing_frame
