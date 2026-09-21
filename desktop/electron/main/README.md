# Electron Main Process

Main process, renderer ile Python core arasindaki guvenli sinirdir.

Pseudocode:

```text
createWindow()
registerIpc("send-text", validate_request, forward_to_python_core)
registerIpc("select-pdf", validate_path, forward_to_python_core)
registerIpc("get-measurements", read_summary_artifact)
```

Node/Electron katmani kriptografik kararlar vermez. Config validation yine ortak Python config/application katmaninda yapilir.
