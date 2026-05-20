const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Authentication
    login: (credentials) => ipcRenderer.invoke('login', credentials),
    backendStatus: () => ipcRenderer.invoke('backend-status'),

    // Temporary access management
    getTemporaryAccess: (token) => ipcRenderer.invoke('get-temporary-access', token),
    addTemporaryAccess: (domain, duration, token) => ipcRenderer.invoke('add-temporary-access', domain, duration, token),
    removeTemporaryAccess: (domain, token) => ipcRenderer.invoke('remove-temporary-access', domain, token),

    // Access requests
    getAccessRequests: (token) => ipcRenderer.invoke('get-access-requests', token),
    approveAccessRequest: (requestId, durationHours, token) => ipcRenderer.invoke('approve-access-request', requestId, durationHours, token),
    rejectAccessRequest: (requestId, reason, token) => ipcRenderer.invoke('reject-access-request', requestId, reason, token),
    requestAccess: (payload, token) => ipcRenderer.invoke('request-access', payload, token),

    // System status
    getSystemStatus: (token) => ipcRenderer.invoke('get-system-status', token),

    // Security features
    predictPhishing: (url, token) => ipcRenderer.invoke('predict-phishing', url, token),
    predictNetwork: (features, token) => ipcRenderer.invoke('predict-network', features, token),
    compareSignature: (content, token) => ipcRenderer.invoke('compare-signature', content, token),
    scanFile: (filePath, token) => ipcRenderer.invoke('scan-file', filePath, token),

    // User management
    getUsers: (token) => ipcRenderer.invoke('get-users', token),
    createUser: (userData, token) => ipcRenderer.invoke('create-user', userData, token),
    deleteUser: (userId, token) => ipcRenderer.invoke('delete-user', userId, token),

    // Blacklist management
    getBlacklist: (token) => ipcRenderer.invoke('get-blacklist', token),
    addBlacklist: (domain, token) => ipcRenderer.invoke('add-blacklist', domain, token),
    removeBlacklist: (domain, token) => ipcRenderer.invoke('remove-blacklist', domain, token),

    // File operations
    selectDirectory: () => ipcRenderer.invoke('select-directory'),
    selectFile: () => ipcRenderer.invoke('select-file'),
    readFileContent: (filePath) => ipcRenderer.invoke('read-file-content', filePath),
    scanFolderSignatures: (folderPath, token) => ipcRenderer.invoke('scan-folder-signatures', folderPath, token),

    // Notifications
    showNotification: (title, body) => ipcRenderer.invoke('show-notification', title, body),

    // Utilities
    networkFeatures: () => ipcRenderer.invoke('network-features'),
    dnsLookup: (domain, token) => ipcRenderer.invoke('dns-lookup', domain, token)
});