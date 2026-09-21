"""PSEUDOCODE: Console output, audit ve measurement ayrimi."""


def display_plaintext_for_assignment(message):
    # Odev demonstrasyonu icin sunucu konsoluna basilir.
    print("Received plaintext:", message)


def audit_event(event_name, metadata):
    # Kalici kayitta mesaj icerigi, key, token veya PDF byte'i tutulmaz.
    write_structured_log({
        "event": event_name,
        "message_id": metadata.message_id,
        "sender_id": metadata.sender_id,
        "receiver_id": metadata.receiver_id,
        "payload_size": metadata.payload_size,
    })


def record_measurement(method, generation_ms, exchange_ms, network_bytes):
    # Ham tekrar JSON'a, ozet CSV'ye yazilir.
    append_json("artifacts/measurements/raw.json", {
        "method": method,
        "key_generation_ms": generation_ms,
        "key_exchange_ms": exchange_ms,
        "network_bytes": network_bytes,
    })
