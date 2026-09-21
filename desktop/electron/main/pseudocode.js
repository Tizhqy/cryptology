// PSEUDOCODE: Electron main process.
// Renderer'dan gelen komutlari validate edip Python core bridge'e aktarir.

ipcMain.handle('send-text', async (_event, request) => {
  validateTextRequest(request);
  return pythonBridge.sendText(request.text, request.receiverId);
});

ipcMain.handle('send-pdf', async (_event, request) => {
  validatePdfPath(request.path);
  return pythonBridge.sendPdf(request.path, request.receiverId);
});

ipcMain.handle('select-profile', async (_event, request) => {
  validateAllowedProfile(request.profile);
  return pythonBridge.reloadConfig(request.profile);
});
