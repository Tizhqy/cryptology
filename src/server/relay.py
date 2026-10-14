"""Minimal plaintext relay for the first end-to-end project milestone."""
# this file manages the connection between client a and client b,
# takes msg from one to another
# 14.10.2026-> there is no encryption at the moment


from __future__ import annotations

import hashlib      #our summary verifier
import socket
import threading    #manage more than one client connection at once
import uuid         #unique pdf ids
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.protocol.framing import ProtocolError, receive_frame, send_frame

# relay.py does not create the frame format. It reads frames with receive_frame,
# sends them with send_frame, and raises ProtocolError for invalid messages.

@dataclass
# A ConnectedClient stores one client's ID and its open TCP connection.
class ConnectedClient:
    client_id: str              #client-a
    connection: socket.socket   #open tcp connection with client-a
    send_lock: threading.Lock = field(default_factory=threading.Lock)
                # Each client has its own lock; it prevents overlapping sends on that connection.
    def send(self, header: dict[str, Any], payload: bytes = b"") -> None:
        with self.send_lock:
            send_frame(self.connection, header, payload)

class RelayServer:
    # The server is the transfer hub: both clients connect here, not to each other.
    def __init__(
        self,
        host: str,
        port: int,
        max_file_size_bytes: int,
        chunk_size_bytes: int,
        received_directory: str | Path = "received",
    ) -> None:
        self.host = host
        self.port = port
        self.max_file_size_bytes = max_file_size_bytes
        self.chunk_size_bytes = chunk_size_bytes
        self.received_directory = Path(received_directory)
        self._clients: dict[str, ConnectedClient] = {}
        self._clients_lock = threading.Lock()  # Protects the shared client list between threads.
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None

    def start(self) -> None:  # Start listening for TCP connections.
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen()
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._accept_thread.start()
        print(f"Server listening on {self.host}:{self.port}", flush=True)

    def stop(self) -> None:  # Close the listener and connected clients.
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        with self._clients_lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            client.connection.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1)

    def _accept_connections(self) -> None:  # Wait for clients and give each one a handler thread.
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            print(f"Connection from {address[0]}:{address[1]}", flush=True)
            threading.Thread(target=self._handle_connection, args=(connection,), daemon=True).start()

    def _handle_connection(self, connection: socket.socket) -> None:
        # The first frame identifies the client; later frames contain its messages.
        client: ConnectedClient | None = None
        # Keep progress for PDF transfers started on this connection.
        active_files: dict[str, dict[str, Any]] = {}
        try:
            registration = receive_frame(connection, 0)
            if registration is None:
                return
            header, _ = registration
            if header.get("message_type") != "register":
                raise ProtocolError("First frame must register the client")
            client_id = header.get("client_id")
            if client_id not in {"client-a", "client-b"}:
                raise ProtocolError("client_id must be client-a or client-b")

            client = ConnectedClient(client_id, connection)
            # Add this connection to the shared client list.
            with self._clients_lock:
                previous = self._clients.get(client_id)
                self._clients[client_id] = client
            if previous is not None:
                previous.connection.close()
            client.send({"message_type": "registered", "client_id": client_id})
            print(f"Registered {client_id}", flush=True)

            while not self._stop.is_set():
                # Read one complete frame, then ask the relay logic to route it.
                result = receive_frame(connection, self.max_file_size_bytes)
                if result is None:
                    break
                frame_header, payload = result
                self._relay_frame(client, frame_header, payload, active_files)
        except (OSError, ProtocolError, ValueError) as error:
            if not self._stop.is_set():
                print(f"Client connection ended: {error}", flush=True)
        finally:
            for file_state in active_files.values():
                file_state["file"].close()
            if client is not None:
                with self._clients_lock:
                    if self._clients.get(client.client_id) is client:
                        del self._clients[client.client_id]
                print(f"Disconnected {client.client_id}", flush=True)
            connection.close()

    def _relay_frame(
        self,
        sender: ConnectedClient,
        header: dict[str, Any],
        payload: bytes,
        active_files: dict[str, dict[str, Any]],
    ) -> None:
        # Find the destination from receiver_id; clients do not connect directly.
        message_type = header.get("message_type")
        receiver_id = header.get("receiver_id")
        if receiver_id not in {"client-a", "client-b"} or receiver_id == sender.client_id:
            raise ProtocolError("Invalid receiver_id")

        with self._clients_lock:
            receiver = self._clients.get(receiver_id)
        if receiver is None:
            sender.send({"message_type": "error", "detail": f"{receiver_id} is not connected"})
            return

        outgoing = dict(header)
        outgoing["sender_id"] = sender.client_id

        if message_type == "text":
            # This first milestone is insecure, so the server can read the text.
            text = payload.decode("utf-8")
            print(f"Plaintext from {sender.client_id} to {receiver_id}: {text}", flush=True)
            receiver.send(outgoing, payload)
            sender.send({"message_type": "ack", "message_id": header.get("message_id")})
            return

        file_id = header.get("file_id")
        if not isinstance(file_id, str) or not file_id:
            raise ProtocolError("File frame is missing file_id")

        if message_type == "file_start":
            # Check PDF metadata and prepare a server-side file for incoming chunks.
            file_name = Path(str(header.get("file_name", ""))).name
            file_size = header.get("file_size")
            expected_hash = header.get("sha256")
            if not file_name.lower().endswith(".pdf"):
                raise ProtocolError("Only PDF files are allowed")
            if not isinstance(file_size, int) or not 0 <= file_size <= self.max_file_size_bytes:
                raise ProtocolError("PDF exceeds configured maximum size")
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                raise ProtocolError("Invalid PDF SHA-256")
            self.received_directory.mkdir(parents=True, exist_ok=True)
            stored_name = f"{uuid.uuid4().hex}_{file_name}"
            output = (self.received_directory / stored_name).open("wb")
            active_files[file_id] = {
                "file": output,
                "hash": hashlib.sha256(),
                "size": 0,
                "expected_size": file_size,
                "expected_hash": expected_hash,
                "next_sequence": 0,
                "stored_name": stored_name,
            }
            outgoing["file_name"] = file_name
            receiver.send(outgoing)
            return

        state = active_files.get(file_id)
        if state is None:
            raise ProtocolError("File transfer was not started")

        if message_type == "file_chunk":
            # Check order and size, save this chunk, then forward it to the receiver.
            sequence = header.get("sequence_number")
            if sequence != state["next_sequence"]:
                raise ProtocolError("Unexpected PDF chunk sequence")
            if len(payload) > self.chunk_size_bytes:
                raise ProtocolError("PDF chunk exceeds configured chunk size")
            state["file"].write(payload)
            state["hash"].update(payload)
            state["size"] += len(payload)
            state["next_sequence"] += 1
            receiver.send(outgoing, payload)
            return

        if message_type == "file_complete":
            # Check the final size and SHA-256 before confirming the transfer.
            state["file"].close()
            del active_files[file_id]
            if state["size"] != state["expected_size"]:
                raise ProtocolError("Received PDF size does not match metadata")
            if state["hash"].hexdigest() != state["expected_hash"]:
                raise ProtocolError("Received PDF SHA-256 does not match metadata")
            print(f"Saved PDF on server: {state['stored_name']}", flush=True)
            receiver.send(outgoing)
            sender.send({"message_type": "ack", "message_id": file_id})
            return

        raise ProtocolError(f"Unsupported message_type: {message_type}")


    # Example: Client A sends a plaintext message to Client B through this server.
    # 1. Client A connects and registers with client_id="client-a".
    # 2. Client B connects and registers with client_id="client-b".
    # 3. Client A sends this frame; send_frame adds payload_length to the header.
    # header_from_a = {
    #     "message_type": "text",
    #     "sender_id": "client-a",
    #     "receiver_id": "client-b",
    #     "message_id": "message-001",
    # }
    # payload_from_a = "Hello, Client B".encode("utf-8")
    #
    # 4. _handle_connection reads the frame from Client A.
    # 5. _relay_frame finds Client B using receiver_id and sends the frame to B.
    # 6. Client B reads the frame and decodes the payload as text.
    # 7. The server sends an ACK back to Client A.
    # This example uses insecure mode, so the text is readable in Wireshark.