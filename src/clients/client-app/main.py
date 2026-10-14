"""Run one client instance; use separate configs for Client A and Client B."""
# this file runs one client and lets it send and receive messages through the server.

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from shared.protocol.framing import ProtocolError, receive_frame, send_frame  # noqa: E402


class Client:   # manages the client connection and receive/send operations
    def __init__(self, settings: dict[str, Any], mode: str, download_directory: str) -> None:
        self.settings = settings
        self.mode = mode
        self.client_id = settings["node"]["client_id"]
        self.receiver_id = "client-b" if self.client_id == "client-a" else "client-a"
        self.max_file_size = settings["transfer"]["max_file_size_bytes"]
        self.chunk_size = settings["transfer"]["chunk_size_bytes"]
        self.download_directory = Path(download_directory)
        self.connection: socket.socket | None = None
        self.send_lock = threading.Lock()
        self.stop_event = threading.Event()
        self._receive_thread: threading.Thread | None = None

    def connect(self) -> None:  # opens tcp conneciton on server, reports the client id and waits for server approval
        node = self.settings["node"]
        self.connection = socket.create_connection((node["server_host"], node["server_port"]))
        self.send({"message_type": "register", "client_id": self.client_id})
        response = receive_frame(self.connection, 0)
        if response is None or response[0].get("message_type") != "registered":
            raise ConnectionError("Server did not register this client")
        self.connection.settimeout(None)
        print(f"Connected as {self.client_id}; sending to {self.receiver_id}")
        self._receive_thread = threading.Thread(target=self._receive_loop)
        self._receive_thread.start()

    def send(self, header: dict[str, Any], payload: bytes = b"") -> None:
        # Check the connection, then ask framing.py to package and send the frame.
        if self.connection is None:
            raise ConnectionError("Client is not connected")
        with self.send_lock:
            send_frame(self.connection, header, payload)

    def send_text(self, text: str) -> None:
        # Convert the text to UTF-8 bytes and prepare its message header.
        # send() passes these separate parts to framing.py.
        self.send({
            "message_type": "text",
            "receiver_id": self.receiver_id,
            "message_id": uuid.uuid4().hex,
        }, text.encode("utf-8"))

    def send_pdf(self, path: Path) -> None: # pdf check; size, hash and separate the file
        # Send file metadata first, then chunks, and finally a completion frame.
        if path.suffix.lower() != ".pdf":
            raise ValueError("Only PDF files are supported")
        file_size = path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(f"PDF exceeds configured maximum of {self.max_file_size} bytes")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(self.chunk_size):
                digest.update(chunk)
        file_id = uuid.uuid4().hex
        common = {"receiver_id": self.receiver_id, "file_id": file_id}
        self.send({
            **common,
            "message_type": "file_start",
            "file_name": path.name,
            "file_size": file_size,
            "sha256": digest.hexdigest(),
        })
        with path.open("rb") as source:
            sequence = 0
            while chunk := source.read(self.chunk_size):
                self.send({
                    **common,
                    "message_type": "file_chunk",
                    "sequence_number": sequence,
                }, chunk)
                sequence += 1
        self.send({**common, "message_type": "file_complete"})
        print(f"Sent {path.name} in {sequence} chunks")

    def _receive_loop(self) -> None:
        # Keep reading frames from the server while this client is connected.
        assert self.connection is not None
        active_files: dict[str, dict[str, Any]] = {}
        try:
            while not self.stop_event.is_set():
                result = receive_frame(self.connection, self.max_file_size)
                if result is None:
                    break
                header, payload = result
                message_type = header.get("message_type")
                if message_type == "text":
                    text = payload.decode("utf-8")
                    print(f"\n[{header.get('sender_id')}] {text}")
                elif message_type == "ack":
                    print(f"\nACK: {header.get('message_id')}")
                elif message_type == "error":
                    print(f"\nServer error: {header.get('detail')}")
                elif message_type == "file_start":
                    self._start_file(header, active_files)
                elif message_type == "file_chunk":
                    self._write_chunk(header, payload, active_files)
                elif message_type == "file_complete":
                    self._complete_file(header, active_files)
        except (OSError, ProtocolError, ValueError) as error:
            if not self.stop_event.is_set():
                print(f"Receive loop stopped: {error}")
        finally:
            for file_state in active_files.values():
                file_state["file"].close()

    def _start_file(self, header: dict[str, Any], active_files: dict[str, dict[str, Any]]) -> None:
        file_id = header["file_id"]
        file_name = Path(header["file_name"]).name
        self.download_directory.mkdir(parents=True, exist_ok=True)
        output_path = self.download_directory / f"{file_id[:8]}_{file_name}"
        active_files[file_id] = {
            "file": output_path.open("wb"),
            "path": output_path,
            "hash": hashlib.sha256(),
            "size": 0,
            "expected_size": header["file_size"],
            "expected_hash": header["sha256"],
            "next_sequence": 0,
        }
        print(f"\nReceiving PDF: {output_path.name}")

    def _write_chunk(
        self,
        header: dict[str, Any],
        payload: bytes,
        active_files: dict[str, dict[str, Any]],
    ) -> None:
        state = active_files[header["file_id"]]
        if header["sequence_number"] != state["next_sequence"]:
            raise ProtocolError("Unexpected PDF chunk sequence")
        state["file"].write(payload)
        state["hash"].update(payload)
        state["size"] += len(payload)
        state["next_sequence"] += 1

    @staticmethod
    def _complete_file(header: dict[str, Any], active_files: dict[str, dict[str, Any]]) -> None:
        state = active_files.pop(header["file_id"])
        state["file"].close()
        if state["size"] != state["expected_size"]:
            raise ProtocolError("Received PDF size does not match metadata")
        if state["hash"].hexdigest() != state["expected_hash"]:
            raise ProtocolError("Received PDF SHA-256 does not match metadata")
        print(f"PDF saved and verified: {state['path']}")

    def close(self) -> None:
        self.stop_event.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        if self._receive_thread is not None:
            self._receive_thread.join()


def main() -> None:
    # Load one client's config, connect it, then handle user commands.
    parser = argparse.ArgumentParser(description="Cryptology lab client")
    parser.add_argument("--config", required=True, help="Path to client-a.json or client-b.json")
    parser.add_argument("--mode", choices=["insecure"], required=True)
    parser.add_argument("--downloads", default="downloads")
    arguments = parser.parse_args()
    settings = json.loads(Path(arguments.config).read_text(encoding="utf-8"))

    client = Client(settings, arguments.mode, arguments.downloads)
    try:
        client.connect()
        print("Type a message, /file <path-to-pdf>, or /quit")
        while True:
            command = input("> ").strip()
            if command == "/quit":
                break
            if command.startswith("/file "):
                client.send_pdf(Path(command[6:].strip().strip('"')))
            elif command:
                client.send_text(command)
    except (OSError, ValueError, ConnectionError) as error:
        print(f"Client error: {error}")
        raise SystemExit(1) from error
    finally:
        client.close()


if __name__ == "__main__":
    main()


# Project flow: Client A sends a text message to Client B through the server.
# 1. src/server/main.py loads server.json and starts RelayServer.
# 2. This file's main() loads client-a.json or client-b.json and connects that client.
# 3. Client.send_text() encodes text as UTF-8 and prepares the header.
# 4. Client.send() calls send_frame() from src/shared/protocol/framing.py.
# 5. RelayServer._handle_connection() reads the frame with receive_frame().
# 6. RelayServer._relay_frame() finds receiver_id and forwards the frame with send_frame().
# 7. The receiving client's _receive_loop() reads the frame and displays the text.
# 8. The server sends an ACK to the sending client.
#
# For a PDF, Client.send_pdf() sends file_start, file_chunk, and file_complete frames.
# The server saves and forwards the chunks; the receiving client rebuilds and verifies the PDF.
# This first milestone is insecure: text and PDF payloads are not encrypted.