from __future__ import annotations

import hashlib
import importlib.util
import socket
import threading
import time
import uuid
from pathlib import Path

from server.relay import RelayServer
from shared.protocol.framing import receive_frame, send_frame

CLIENT_MAIN_PATH = Path(__file__).resolve().parents[2] / "src" / "clients" / "client-app" / "main.py"
CLIENT_SPEC = importlib.util.spec_from_file_location("cryptology_client_main", CLIENT_MAIN_PATH)
assert CLIENT_SPEC is not None and CLIENT_SPEC.loader is not None
CLIENT_MODULE = importlib.util.module_from_spec(CLIENT_SPEC)
CLIENT_SPEC.loader.exec_module(CLIENT_MODULE)
Client = CLIENT_MODULE.Client


def _connect_client(port: int, client_id: str) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
    send_frame(connection, {"message_type": "register", "client_id": client_id})
    response = receive_frame(connection, 0)
    assert response is not None
    assert response[0]["message_type"] == "registered"
    return connection


def test_insecure_text_is_relayed_between_two_clients(tmp_path) -> None:
    relay = RelayServer("127.0.0.1", 0, 1024 * 1024, 4096, tmp_path)
    relay.start()
    client_a = client_b = None
    try:
        deadline = time.monotonic() + 2
        while relay.port == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        client_a = _connect_client(relay.port, "client-a")
        client_b = _connect_client(relay.port, "client-b")
        message_id = uuid.uuid4().hex
        send_frame(client_a, {
            "message_type": "text",
            "receiver_id": "client-b",
            "message_id": message_id,
        }, b"hello from client A")

        received = receive_frame(client_b, 1024)
        acknowledgement = receive_frame(client_a, 1024)

        assert received is not None
        assert received[0]["sender_id"] == "client-a"
        assert received[1] == b"hello from client A"
        assert acknowledgement is not None
        assert acknowledgement[0]["message_type"] == "ack"
        assert acknowledgement[0]["message_id"] == message_id
    finally:
        if client_a is not None:
            client_a.close()
        if client_b is not None:
            client_b.close()
        relay.stop()


def test_client_close_waits_for_receive_thread(tmp_path) -> None:
    settings = {
        "node": {"client_id": "client-a"},
        "transfer": {"max_file_size_bytes": 1024, "chunk_size_bytes": 128},
    }
    client = Client(settings, "insecure", str(tmp_path))
    client_socket, peer_socket = socket.socketpair()
    client.connection = client_socket
    client._receive_thread = threading.Thread(target=client._receive_loop)
    client._receive_thread.start()

    try:
        client.close()
        assert not client._receive_thread.is_alive()
    finally:
        peer_socket.close()


def test_insecure_pdf_is_saved_and_relayed(tmp_path) -> None:
    relay = RelayServer("127.0.0.1", 0, 1024 * 1024, 4, tmp_path / "received")
    relay.start()
    client_a = client_b = None
    content = b"%PDF-1.4 sample file"
    file_id = uuid.uuid4().hex
    try:
        client_a = _connect_client(relay.port, "client-a")
        client_b = _connect_client(relay.port, "client-b")
        send_frame(client_a, {
            "message_type": "file_start",
            "receiver_id": "client-b",
            "file_id": file_id,
            "file_name": "sample.pdf",
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
        start_on_b = receive_frame(client_b, 0)
        assert start_on_b is not None
        assert start_on_b[0]["message_type"] == "file_start"

        for sequence, offset in enumerate(range(0, len(content), 4)):
            chunk = content[offset : offset + 4]
            send_frame(client_a, {
                "message_type": "file_chunk",
                "receiver_id": "client-b",
                "file_id": file_id,
                "sequence_number": sequence,
            }, chunk)
            relayed = receive_frame(client_b, 4)
            assert relayed is not None
            assert relayed[1] == chunk

        send_frame(client_a, {
            "message_type": "file_complete",
            "receiver_id": "client-b",
            "file_id": file_id,
        })
        complete_on_b = receive_frame(client_b, 0)
        acknowledgement = receive_frame(client_a, 0)
        assert complete_on_b is not None
        assert complete_on_b[0]["message_type"] == "file_complete"
        assert acknowledgement is not None
        assert acknowledgement[0]["message_type"] == "ack"

        saved_files = list((tmp_path / "received").glob("*.pdf"))
        assert len(saved_files) == 1
        assert saved_files[0].read_bytes() == content
    finally:
        if client_a is not None:
            client_a.close()
        if client_b is not None:
            client_b.close()
        relay.stop()


def test_client_pdf_transfer_rebuilds_file_on_receiver(tmp_path) -> None:
    received_directory = tmp_path / "server-received"
    download_directory = tmp_path / "client-b-downloads"
    relay = RelayServer("127.0.0.1", 0, 1024 * 1024, 257, received_directory)
    relay.start()
    settings = {
        "node": {
            "server_host": "127.0.0.1",
            "server_port": relay.port,
        },
        "transfer": {
            "max_file_size_bytes": 1024 * 1024,
            "chunk_size_bytes": 257,
        },
    }
    settings_a = {**settings, "node": {**settings["node"], "client_id": "client-a"}}
    settings_b = {**settings, "node": {**settings["node"], "client_id": "client-b"}}
    client_a = Client(settings_a, "insecure", str(tmp_path / "client-a-downloads"))
    client_b = Client(settings_b, "insecure", str(download_directory))
    source_pdf = tmp_path / "sample.pdf"
    expected_content = b"%PDF-1.4\n" + bytes(range(256)) * 20 + b"\n%%EOF"
    source_pdf.write_bytes(expected_content)

    try:
        client_a.connect()
        client_b.connect()
        client_a.send_pdf(source_pdf)

        deadline = time.monotonic() + 3
        downloaded_files = []
        while time.monotonic() < deadline:
            downloaded_files = list(download_directory.glob("*_sample.pdf"))
            if downloaded_files and downloaded_files[0].stat().st_size == len(expected_content):
                break
            time.sleep(0.01)

        server_files = list(received_directory.glob("*_sample.pdf"))
        assert len(downloaded_files) == 1
        assert len(server_files) == 1
        assert downloaded_files[0].read_bytes() == expected_content
        assert server_files[0].read_bytes() == expected_content
    finally:
        client_a.close()
        client_b.close()
        relay.stop()