const { app, BrowserWindow, ipcMain, dialog, Notification } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');

app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-software-rasterizer');
app.commandLine.appendSwitch('disable-gpu-compositing');
app.commandLine.appendSwitch('disable-accelerated-2d-canvas');
app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-infobars');
app.commandLine.appendSwitch('disable-backgrounding-occluded-windows');
app.setAppUserModelId('com.shieldguard.app');
app.setPath('userData', path.join(__dirname, 'user_data'));
app.setPath('cache', path.join(__dirname, 'cache'));
app.setPath('temp', path.join(__dirname, 'tmp'));

let mainWindow;
let apiClient = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'assets', 'icon.png'), // Add icon if available
  });

  mainWindow.loadFile('index.html');

  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC handlers for backend communication
ipcMain.handle('login', async (event, credentials) => {
  try {
    const response = await apiClient.post('/login', credentials);
    return response.data;
  } catch (error) {
    let detail = 'Login failed';
    if (error.response) {
      detail = error.response.data?.detail || JSON.stringify(error.response.data) || error.message || detail;
    } else if (error.request) {
      detail = 'Backend unreachable. Make sure the ShieldGuard backend is running on http://127.0.0.1:8000';
    } else if (error.message) {
      detail = error.message;
    }
    console.error('Login error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('backend-status', async () => {
  try {
    await apiClient.get('/openapi.json');
    return { alive: true, message: 'Backend reachable on http://127.0.0.1:8000' };
  } catch (error) {
    let detail = 'Backend unreachable';
    if (error.response) {
      detail = `Backend reachable but returned ${error.response.status}`;
    } else if (error.request) {
      detail = 'Backend unreachable. Check that the FastAPI server is running on port 8000.';
    } else if (error.message) {
      detail = error.message;
    }
    return { alive: false, message: detail };
  }
});

ipcMain.handle('get-users', async (event, token) => {
  try {
    const response = await apiClient.get('/users', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    throw new Error('Failed to get users');
  }
});

ipcMain.handle('create-user', async (event, userData, token) => {
  try {
    const response = await apiClient.post('/admin/create_user', userData, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to create user';
    console.error('Create user error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('delete-user', async (event, userId, token) => {
  try {
    const response = await apiClient.delete(`/admin/delete_user/${userId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to delete user';
    console.error('Delete user error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('scan-path', async (event, path, scanType, token) => {
  try {
    const response = await apiClient.post('/scan_path', { path, scan_type: scanType }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    throw new Error('Scan failed');
  }
});

ipcMain.handle('scan-file', async (event, path, token) => {
  try {
    const response = await apiClient.post('/scan_file', { path }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    let detail = 'Scan failed';
    if (error.response) {
      detail = error.response.data?.detail || JSON.stringify(error.response.data) || error.message || detail;
    } else if (error.request) {
      detail = 'Scan request failed. Check that the backend is running and the file path is accessible.';
    } else if (error.message) {
      detail = error.message;
    }
    console.error('Scan file error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

async function scanFolderRecursively(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await scanFolderRecursively(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

ipcMain.handle('scan-folder-signatures', async (event, folderPath, token) => {
  try {
    const files = await scanFolderRecursively(folderPath);
    const matches = [];
    for (const filePath of files) {
      try {
        const response = await apiClient.post('/scan_file', { path: filePath }, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const result = response.data;
        if (result.findings && result.findings.length > 0) {
          result.findings.forEach(fileResult => {
            if (fileResult.matches && fileResult.matches.length > 0) {
              fileResult.matches.forEach(match => {
                matches.push({ file_path: filePath, signature_id: match.id, description: match.description, similarity: 1.0 });
              });
            }
          });
        }
      } catch (innerError) {
        console.warn(`Failed to scan file ${filePath}:`, innerError.message || innerError);
      }
    }
    return { matches };
  } catch (error) {
    let detail = 'Failed to scan folder signatures';
    if (error.message) {
      detail = error.message;
    }
    console.error('Scan folder signatures error:', detail, error);
    throw new Error(detail);
  }
});

ipcMain.handle('predict-phishing', async (event, url, token) => {
  try {
    const response = await apiClient.post('/predict_phishing', { url }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Prediction failed';
    console.error('Predict phishing error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('get-temporary-access', async (event, token) => {
  try {
    const response = await apiClient.get('/api/whitelist', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to get temporary access entries';
    console.error('Get temporary access error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('add-temporary-access', async (event, domain, duration, token) => {
  try {
    const response = await apiClient.post('/api/whitelist', { domain, duration_hours: duration }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to add temporary access';
    console.error('Add temporary access error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('remove-temporary-access', async (event, domain, token) => {
  try {
    const response = await apiClient.delete(`/api/whitelist/${domain}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to remove temporary access';
    console.error('Remove temporary access error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('get-access-requests', async (event, token) => {
  try {
    const response = await apiClient.get('/api/requests', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to get access requests';
    console.error('Get access requests error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('approve-access-request', async (event, requestId, duration, token) => {
  try {
    const response = await apiClient.post(`/api/requests/${requestId}/approve`, { duration_hours: duration }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to approve request';
    console.error('Approve access request error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('reject-access-request', async (event, requestId, reason, token) => {
  try {
    const response = await apiClient.post(`/api/requests/${requestId}/reject`, { rejection_reason: reason }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to reject request';
    console.error('Reject access request error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('get-system-status', async (event, token) => {
  try {
    const response = await apiClient.get('/api/status', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to get system status';
    console.error('Get system status error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths[0] || null;
});

ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile']
  });
  return result.filePaths[0] || null;
});

ipcMain.handle('dns-lookup', async (event, domain, token) => {
  try {
    const response = await apiClient.post('/dns_lookup', { domain }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    let detail = error.response?.data?.detail || error.message || 'DNS lookup failed';
    if (typeof detail !== 'string') {
      detail = JSON.stringify(detail);
    }
    console.error('DNS lookup error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('request-access', async (event, payload, token) => {
  try {
    const response = await apiClient.post('/api/requests', payload, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Access request failed';
    console.error('Access request error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('network-features', async () => {
  try {
    const response = await apiClient.get('/network_features');
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to load network features';
    console.error('Network features error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('predict-network', async (event, payload, token) => {
  try {
    const requestBody = payload && payload.features ? payload : { features: payload };
    const response = await apiClient.post('/predict_network', requestBody, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Network scan failed';
    console.error('Predict network error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('compare-signature', async (event, content, token) => {
  try {
    const response = await apiClient.post('/compare_signature', { signature: content }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Signature comparison failed';
    console.error('Compare signature error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('show-notification', async (event, title, body) => {
  new Notification({ title, body }).show();
});

ipcMain.handle('get-blacklist', async (event, token) => {
  try {
    const response = await apiClient.get('/api/blacklist', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to get blacklist';
    console.error('Get blacklist error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('add-blacklist', async (event, domain, token) => {
  try {
    const response = await apiClient.post('/api/blacklist', { domain }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to add to blacklist';
    console.error('Add blacklist error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('remove-blacklist', async (event, domain, token) => {
  try {
    // Use query parameter and let backend normalize domain so values with scheme/path work
    const response = await apiClient.delete('/api/blacklist', {
      params: { domain },
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    const detail = error.response?.data?.detail || error.message || 'Failed to remove from blacklist';
    console.error('Remove blacklist error:', detail, error.response?.data, error.code);
    throw new Error(detail);
  }
});

ipcMain.handle('read-file-content', async (event, filePath) => {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    return content;
  } catch (error) {
    throw new Error('Failed to read file: ' + error.message);
  }
});

ipcMain.handle('usb-status', async () => {
  return usbState;
});

let usbState = { available: false, message: 'USB support is unavailable. Install the native usb module to enable it.' };
try {
  const usb = require('usb');
  usbState = { available: true, message: 'USB support is enabled. Attach or detach a device to test.' };

  usb.on('attach', (device) => {
    if (mainWindow) {
      mainWindow.webContents.send('usb-attached', { vendorId: device.deviceDescriptor.idVendor, productId: device.deviceDescriptor.idProduct });
    }
  });

  usb.on('detach', (device) => {
    if (mainWindow) {
      mainWindow.webContents.send('usb-detached', { vendorId: device.deviceDescriptor.idVendor, productId: device.deviceDescriptor.idProduct });
    }
  });
} catch (err) {
  console.warn('USB module not available:', err.message);
}