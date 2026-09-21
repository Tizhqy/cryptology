# GUI Bridge

Electron main process ile Python client application arasindaki dar komut sozlesmesi.

Ornek komutlar:

```text
connect(config_path)
send_text(text, receiver_id)
send_pdf(path, receiver_id)
establish_session(key_exchange)
get_measurement_summary()
```

Bridge, gelen degerleri validate eder ve application use-case'lerine aktarir. Renderer'dan gelen ham path, mode veya key exchange degeri dogrudan socket/crypto koduna gecmez.
