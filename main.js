const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const dataDir = app.getPath('userData');
const notesFile = path.join(dataDir, 'notes.enc');
const passwordsFile = path.join(dataDir, 'passwords.enc');
const remindersFile = path.join(dataDir, 'reminders.enc');
const serversFile = path.join(dataDir, 'servers.enc');
const passwordFile = path.join(dataDir, 'password.enc');

function encryptData(data) {
  const cipher = crypto.createCipher('aes-256-ctr', 'secret-key');
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encrypted) {
  try {
    const decipher = crypto.createDecipher('aes-256-ctr', 'secret-key');
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (e) {
    return [];
  }
}

function ensureFile(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, encryptData([]), 'utf8');
}

function loadData(file) {
  ensureFile(file);
  return decryptData(fs.readFileSync(file, 'utf8'));
}

function saveData(file, data) {
  fs.writeFileSync(file, encryptData(data), 'utf8');
}

// 🧠 Пароль
ipcMain.handle('auth:getStatus', async () => fs.existsSync(passwordFile));

ipcMain.handle('auth:setPassword', async (_, password) => {
  fs.writeFileSync(passwordFile, encryptData({ password }), 'utf8');
  return true;
});

ipcMain.handle('auth:checkPassword', async (_, password) => {
  if (!fs.existsSync(passwordFile)) return false;
  const stored = decryptData(fs.readFileSync(passwordFile, 'utf8'));
  return stored.password === password;
});

// 📝 Заметки
ipcMain.handle('notes:list', () => loadData(notesFile));
ipcMain.handle('notes:create', (_, note) => {
  const data = loadData(notesFile);
  data.push(note);
  saveData(notesFile, data);
  return data;
});
ipcMain.handle('notes:delete', (_, index) => {
  const data = loadData(notesFile);
  data.splice(index, 1);
  saveData(notesFile, data);
  return data;
});

// 🔐 Пароли
ipcMain.handle('passwords:list', () => loadData(passwordsFile));
ipcMain.handle('passwords:create', (_, entry) => {
  const data = loadData(passwordsFile);
  data.push(entry);
  saveData(passwordsFile, data);
  return data;
});
ipcMain.handle('passwords:delete', (_, index) => {
  const data = loadData(passwordsFile);
  data.splice(index, 1);
  saveData(passwordsFile, data);
  return data;
});

// ⏰ Напоминания
ipcMain.handle('reminders:list', () => loadData(remindersFile));
ipcMain.handle('reminders:create', (_, entry) => {
  const data = loadData(remindersFile);
  data.push(entry);
  saveData(remindersFile, data);
  return data;
});
ipcMain.handle('reminders:delete', (_, index) => {
  const data = loadData(remindersFile);
  data.splice(index, 1);
  saveData(remindersFile, data);
  return data;
});

// 🌐 Серверы
ipcMain.handle('servers:list', () => loadData(serversFile));
ipcMain.handle('servers:create', (_, entry) => {
  const data = loadData(serversFile);
  data.push(entry);
  saveData(serversFile, data);
  return data;
});
ipcMain.handle('servers:delete', (_, index) => {
  const data = loadData(serversFile);
  data.splice(index, 1);
  saveData(serversFile, data);
  return data;
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });
  win.loadURL('http://localhost:3000');
}

app.whenReady().then(createWindow);
