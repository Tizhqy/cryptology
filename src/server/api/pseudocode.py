"""PSEUDOCODE: Thin server connection handler."""


def handle_connection(connection, settings, application):
    # TCP framing ayrintisini protocol adapter'a birak.
    frame = protocol.read_frame(connection)

    if frame.message_type == "register":
        application.register_client(frame.sender_id, connection)
        return

    if frame.message_type == "key_exchange":
        application.establish_session_key(frame)
        return

    if frame.message_type in ["text", "file_start", "file_chunk", "file_complete"]:
        application.route_frame(frame)
        return

    # Bilinmeyen frame'ler kontrollu hata ile reddedilir.
    send_error(connection, code="UNSUPPORTED_MESSAGE_TYPE")
