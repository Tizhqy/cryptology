"""Length-prefixed JSON headers with binary TCP payloads."""
# This file helps us send and receive complete messages over TCP.
# 13.10.2026 insecure, just trying to figure thing out
# this file seperates the data that comes from tcp to msgs
# tcp caries a continuous byte stream. it doesn't have the information of this ia msg by itself.
# one message may arrive in multiple reads.
# framing adds lengths so the receiver can find message boundaries

from __future__ import annotations

import json
import socket
import struct
from typing import Any

MAX_HEADER_SIZE = 64 * 1024  #means our header's max size is 64KiB


class ProtocolError(Exception):
    """Raised when a peer sends an invalid or incomplete frame."""


def send_frame(connection: socket.socket, header: dict[str, Any], payload: bytes = b"") -> None:
    frame_header = dict(header)     #copy the header so we do not change the caller's dictionary
    frame_header["payload_length"] = len(payload)
    encoded_header = json.dumps(frame_header, separators=(",", ":")).encode("utf-8")
    #convert the header to compact JSON, then encode it as UTF-8 bytes
    if len(encoded_header) > MAX_HEADER_SIZE:
        raise ProtocolError("Frame header is too large")
    connection.sendall(struct.pack("!I", len(encoded_header)) + encoded_header + payload)
                                        #Send: 4-byte header length + JSON header + payload
# header = {                        carries the information,
#     "message_type": "text",       this msg is text and
#     "sender_id": "client-a"       sender is client-a
# }
# payload = b"Merhaba"              this is our msg


#-> {"message_type":"text","sender_id":"client-a","payload_length":7} this is our msg that came from send_frame
# client b has to make "result = receive_frame(client_b_connection, max_payload_size=1024)" call
# in here client_b_connection is B's tcp connection
def receive_frame(
    connection: socket.socket,
    max_payload_size: int,
) -> tuple[dict[str, Any], bytes] | None:
    # First, read 4 bytes to learn the JSON header size.
    header_length_bytes = _receive_exactly(connection, 4, allow_clean_eof=True)     #firslty it will read the first 4 byte
    if header_length_bytes is None:
        return None

    # Convert the 4 bytes into the number of bytes in the JSON header.
    header_length = struct.unpack("!I", header_length_bytes)[0]
    if not 1 <= header_length <= MAX_HEADER_SIZE:
        raise ProtocolError("Invalid frame header length")

    # Read the full JSON header and convert it back into a Python dictionary.
    encoded_header = _receive_exactly(connection, header_length)
    try:
        header = json.loads(encoded_header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("Invalid JSON frame header") from error
    if not isinstance(header, dict):
        raise ProtocolError("Frame header must be a JSON object")

    # The JSON header tells us how many payload bytes to read.
    payload_length = header.get("payload_length")
    if not isinstance(payload_length, int) or not 0 <= payload_length <= max_payload_size:
        raise ProtocolError("Invalid frame payload length")

    # Read the payload, then return both parts to the caller.
    payload = _receive_exactly(connection, payload_length) if payload_length else b""
    return header, payload


def _receive_exactly(
    connection: socket.socket,  #tcp connection that is going to read
    size: int,                  #number of bytes going to collect
    *,
    allow_clean_eof: bool = False,
) -> bytes | None:
    data = bytearray()
    # TCP may give us fewer bytes than requested, so keep reading until complete.
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            # No bytes means a clean close only when this frame has not started.
            if allow_clean_eof and not data:
                return None
            raise ProtocolError("Connection closed in the middle of a frame")
        data.extend(chunk)
    return bytes(data)


# Example: Client A sends "Merhaba" to Client B through the server.
# 1. Client A creates a header and encodes the message as bytes.
# client_a_header = {
#     "message_type": "text",
#     "sender_id": "client-a",
#     "receiver_id": "client-b",
# }
# client_a_payload = "Merhaba".encode("utf-8")
# send_frame(client_a_connection, client_a_header, client_a_payload)
#
# 2. The server reads the complete frame from Client A.
# received_from_a = receive_frame(server_connection_to_a, max_payload_size=1024)
#
# 3. The server forwards the same header and payload to Client B.
# if received_from_a is not None:
#     header, payload = received_from_a
#     send_frame(server_connection_to_b, header, payload)
#
# 4. Client B reads the frame and turns the payload bytes back into text.
# received_by_b = receive_frame(client_b_connection, max_payload_size=1024)
# if received_by_b is not None:
#     header, payload = received_by_b
#     print(header["sender_id"])  # client-a
#     print(payload.decode("utf-8"))  # Merhaba
# This example is insecure: the payload is sent as readable text.