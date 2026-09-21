"""PSEUDOCODE: TCP server lifecycle."""


def start_server(settings, connection_handler):
    listener = TcpListener(settings.node.bind_host, settings.node.bind_port)
    listener.start()

    while True:
        connection = listener.accept()
        # Her connection ayri worker/task ile ele alinabilir.
        spawn(connection_handler, connection)


def read_exactly(connection, amount):
    # TCP read tek seferde istenen byte sayisini vermeyebilir.
    # Bu nedenle amount tamamlanana kadar okumaya devam edilir.
    buffer = bytearray()
    while len(buffer) < amount:
        part = connection.receive(amount - len(buffer))
        if not part:
            raise ConnectionClosed()
        buffer.extend(part)
    return bytes(buffer)
