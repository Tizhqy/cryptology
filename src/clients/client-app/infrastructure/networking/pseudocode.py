"""PSEUDOCODE: Client TCP transport."""


class TcpClientTransport:
    def connect(self, host, port):
        # Config'teki host/port ile server'a baglan.
        self.connection = tcp_connect(host, port)
        self.send(register_frame(client_id=settings.node.client_id))

    def send(self, frame):
        # Frame serializer length prefix ekler; TCP partial write kontrol edilir.
        encoded = encode_frame(frame)
        write_all(self.connection, encoded)

    def receive(self):
        # Server ACK veya incoming message frame'ini okur.
        return read_frame(self.connection)
