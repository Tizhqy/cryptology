# Electron Desktop Adapter

Electron arayuzu ilk core uygulama degildir. Once Python CLI ve use-case'ler dogrulanir; sonra bu klasor ayni fonksiyonlari masaustu arayuzunden cagirmak icin kullanilir.

## UI siniri

- Renderer: HTML/CSS/JavaScript ile form, mesaj listesi, progress ve measurement table.
- Main process: IPC, config secimi ve local Python bridge.
- Python core: TCP, AES, key exchange, PDF chunking ve audit.

Electron renderer icinde AES, RSA veya socket kodu yazilmaz. GUI butonu yalnizca bir use-case komutu gonderir:

```text
Send text button -> IPC -> client application -> TCP server
Select PDF      -> IPC -> client application -> chunk transfer
Mode/key method  -> config command -> validated settings
```

## En dusuk yuklu entegrasyon

Ilk Electron denemesinde main process, Python client'i local process olarak baslatip stdin/stdout veya local IPC ile konusabilir. Daha sonra gerekirse local HTTP bridge'e gecilebilir. Bu karar Python core tamamlandiktan sonra verilecek.
