"""PSEUDOCODE: TCP frame sozlesmesi."""


class Frame:
    version: int
    message_type: str
    sender_id: str
    receiver_id: str
    message_id: str
    sequence_number: int
    total_chunks: int
    nonce: bytes
    auth_tag: bytes
    payload: bytes


def encode_frame(frame):
    # JSON header, binary payload'dan once gonderilir.
    header = serialize_json({
        "version": frame.version,
        "message_type": frame.message_type,
        "sender_id": frame.sender_id,
        "receiver_id": frame.receiver_id,
        "message_id": frame.message_id,
        "sequence_number": frame.sequence_number,
        "total_chunks": frame.total_chunks,
        "nonce": base64_encode(frame.nonce),
        "auth_tag": base64_encode(frame.auth_tag),
        "payload_length": len(frame.payload),
    })

    # Receiver once header uzunlugunu okuyup sonra tam header ve payload'u okur.
    return encode_uint32(len(header)) + header + frame.payload


def read_frame(connection):
    header_length = read_exactly(connection, 4)
    header = read_exactly(connection, decode_uint32(header_length))
    metadata = parse_json(header)
    payload = read_exactly(connection, metadata["payload_length"])
    return Frame.from_metadata_and_payload(metadata, payload)
