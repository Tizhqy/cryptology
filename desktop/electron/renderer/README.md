# Electron Renderer

Bu katman sadece arayuz taslagi icindir.

Planlanan ekranlar:

- Server host/port
- Client ID
- Secure/insecure mode
- RSA/DH/ECDH/ML-KEM secimi
- Library/manual AES deney secimi
- Text input
- PDF file picker
- Transfer progress
- Incoming messages
- Benchmark result table

Renderer dogrudan Python modullerini import etmez; Electron IPC kanalini kullanir.
