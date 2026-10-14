"""Run the first milestone's plaintext TCP relay server."""
# This file loads the server config, starts the relay server, and stops it when requested.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from relay import RelayServer


def main() -> None:
    # Read command-line options for the config file and lab mode.
    parser = argparse.ArgumentParser(description="Cryptology lab relay server")
    parser.add_argument("--config", default="config/server.json")
    # This first milestone only supports insecure plaintext mode.
    parser.add_argument("--mode", choices=["insecure"], required=True)
    parser.add_argument("--received-dir", default="received")
    arguments = parser.parse_args()

    # Load server address and file transfer limits from the JSON config.
    settings = json.loads(Path(arguments.config).read_text(encoding="utf-8"))
    node = settings["node"]
    transfer = settings["transfer"]

    # Create the relay server with the settings loaded above.
    server = RelayServer(
        host=node["bind_host"],
        port=node["bind_port"],
        max_file_size_bytes=transfer["max_file_size_bytes"],
        chunk_size_bytes=transfer["chunk_size_bytes"],
        received_directory=arguments.received_dir,
    )

    # Start listening; the server accepts client connections in the background.
    server.start()
    try:
        # Keep this program open until Enter or Ctrl+C is pressed.
        while True:
            input("Server running. Press Enter to stop. ")
            break
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()


# Example: Client A sends a message to Client B through this server.
# 1. Terminal 1: start the server.
# python src/server/main.py --config config/server.json --mode insecure
#
# 2. Terminal 2: start Client B and wait for a message.
# python src/clients/client-app/main.py --config config/client-b.json --mode insecure
#
# 3. Terminal 3: start Client A.
# python src/clients/client-app/main.py --config config/client-a.json --mode insecure
#
# 4. Type a message in Client A. It sends the frame to the server.
# 5. The server uses receiver_id to forward the frame to Client B.
# 6. Client B displays the message; the server sends an ACK to Client A.
# Press Enter in Terminal 1 to stop the server.