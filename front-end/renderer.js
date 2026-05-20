// Global state
let currentToken = null;
let currentUser = null;
let networkScanInterval = null;
let temporaryAccessInterval = null;
let activeBlacklistInterval = null;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    checkBackendStatus();
});

// Setup event listeners
function setupEventListeners() {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = tab.dataset.tab || tab.textContent.toLowerCase().replace(/\s+/g, '');
            showTab(tabName, tab);
        });
    });
}

// Update UI visibility based on user role
function updateUIVisibility() {
    const isAdmin = currentUser && currentUser.role && currentUser.role.toLowerCase() === 'admin';
    document.getElementById('dashboardTitle').textContent = isAdmin ? '🛡️ ShieldGuard Admin' : '🛡️ ShieldGuard';
    document.getElementById('dashboardSubtitle').textContent = isAdmin ? 'Manage your network protections and user access.' : 'Submit temporary access requests and review your request status.';

    // Show or hide admin-only elements for non-admins
    const adminElements = document.querySelectorAll('.admin-only');
    adminElements.forEach(el => {
        el.style.display = isAdmin ? 'block' : 'none';
    });

    // Hide user-only elements for admins (if any)
    const userElements = document.querySelectorAll('.user-only');
    userElements.forEach(el => {
        el.style.display = isAdmin ? 'none' : 'block';
    });

    // Ensure non-admin users land on the access requests tab
    if (!isAdmin) {
        showTab('requests');
    }
}

// Login handling
async function handleLogin(e) {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const result = await window.electronAPI.login({ username, password });
        currentToken = result.token;
        currentUser = { username: result.username, role: result.role };

        document.getElementById('login').classList.add('hidden');
        document.getElementById('adminDashboard').classList.remove('hidden');

        updateUIVisibility();
        loadDashboard();
        showTab(currentUser.role && currentUser.role.toLowerCase() === 'admin' ? 'temporary' : 'requests');
    } catch (error) {
        document.getElementById('loginError').textContent = error.message;
    }
}

// Tab switching
function showTab(tabName, clickedTab) {
    const tabMap = {
        temporary: 'temporary',
        requests: 'requests',
        security: 'security',
        users: 'users',
        settings: 'settings',
        accessrequests: 'requests',
        access: 'requests'
    };
    const normalizedTab = tabMap[tabName] || tabName;

    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    // Remove active class from all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });

    // Clear any periodic refresh interval when leaving a tab
    clearTemporaryAccessInterval();
    clearBlacklistInterval();

    const targetTab = document.getElementById(normalizedTab + 'Tab');
    if (targetTab) {
        targetTab.classList.remove('hidden');
    }

    // Add active class to clicked tab
    if (clickedTab) clickedTab.classList.add('active');

    // Load tab data
    switch(normalizedTab) {
        case 'temporary':
            loadTemporaryAccess();
            break;
        case 'requests':
            loadAccessRequests();
            break;
        case 'security':
            loadBlacklist();
            break;
        case 'users':
            loadUsers();
            break;
        case 'settings':
            checkBackendStatus();
            break;
    }
}

// Load dashboard overview
async function loadDashboard() {
    try {
        const status = await window.electronAPI.getSystemStatus(currentToken);

        // Update system status
        const statusIndicator = document.getElementById('systemStatus');
        if (status.proxy_running && status.backend_running) {
            statusIndicator.className = 'status-indicator status-online';
            statusIndicator.innerHTML = '<span>●</span><span>System Online</span>';
        } else {
            statusIndicator.className = 'status-indicator status-offline';
            statusIndicator.innerHTML = '<span>●</span><span>System Offline</span>';
        }

        // Update metrics
        document.getElementById('activeProtections').textContent = status.blocked_domains || 0;
        document.getElementById('pendingRequests').textContent = status.pending_requests || 0;
        document.getElementById('temporaryAccessCount').textContent = status.temporary_unblocks || 0;
        document.getElementById('systemUptime').textContent = status.uptime_hours != null ? status.uptime_hours : '--';

    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// Load temporary access entries
async function loadTemporaryAccess() {
    try {
        const entries = await window.electronAPI.getTemporaryAccess(currentToken);
        const tbody = document.getElementById('temporaryBody');

        if (temporaryAccessInterval) {
            clearInterval(temporaryAccessInterval);
            temporaryAccessInterval = null;
        }

        if (!Array.isArray(entries) || entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #94a3b8;">No temporary access entries</td></tr>';
            return;
        }

        tbody.innerHTML = entries.map(item => {
            const expiresAt = item.expires_at ? new Date(item.expires_at) : null;
            const timeLeft = expiresAt ? formatTimeLeft(expiresAt) : 'Never';
            return `
                <tr data-domain="${item.domain}" data-expires-at="${item.expires_at || ''}">
                    <td>${item.domain}</td>
                    <td>${item.added_by || 'admin'}</td>
                    <td>${expiresAt ? expiresAt.toLocaleString() : 'Never'}</td>
                    <td class="countdown-cell">${timeLeft}</td>
                    <td>
                        <button class="btn btn-danger" onclick="removeTemporaryAccess('${item.domain}')">Remove</button>
                    </td>
                </tr>
            `;
        }).join('');

        temporaryAccessInterval = setInterval(updateTemporaryAccessCountdown, 1000);

    } catch (error) {
        document.getElementById('temporaryBody').innerHTML =
            '<tr><td colspan="5" style="text-align: center; color: #ef4444;">Failed to load temporary access entries</td></tr>';
    }
}

function clearTemporaryAccessInterval() {
    if (temporaryAccessInterval) {
        clearInterval(temporaryAccessInterval);
        temporaryAccessInterval = null;
    }
}

function updateTemporaryAccessCountdown() {
    const rows = document.querySelectorAll('#temporaryBody tr[data-domain]');
    const now = new Date();
    rows.forEach(row => {
        const expiresAtRaw = row.getAttribute('data-expires-at');
        const countdownCell = row.querySelector('.countdown-cell');
        if (!countdownCell) return;
        if (!expiresAtRaw) {
            countdownCell.textContent = 'Never';
            return;
        }
        const expiresAt = new Date(expiresAtRaw);
        const timeLeft = formatTimeLeft(expiresAt, now);
        countdownCell.textContent = timeLeft;

        // If expired, trigger a one-time refresh to pick up re-blocking by the backend
        if (expiresAt <= now && !row.dataset.expiredHandled) {
            row.dataset.expiredHandled = '1';
            // Defer refresh slightly to allow backend cleanup task to run
            setTimeout(async () => {
                try {
                    await loadTemporaryAccess();
                    await loadBlacklist();
                    await loadDashboard();
                } catch (e) {
                    console.error('Error refreshing lists after expiry:', e);
                }
            }, 1500);
        }
    });
}

function formatTimeLeft(expiresAt, now = new Date()) {
    if (!expiresAt || isNaN(expiresAt.getTime())) {
        return 'Never';
    }
    const diffSeconds = Math.ceil((expiresAt - now) / 1000);
    if (diffSeconds <= 0) {
        return 'Expired';
    }
    let diff = diffSeconds;
    const hours = Math.floor(diff / 3600);
    diff %= 3600;
    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;
    if (hours > 0) {
        return `${hours}h ${minutes}m ${seconds}s`;
    }
    if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    }
    return `${seconds}s`;
}

// Remove temporary access entry
async function removeTemporaryAccess(domain) {
    if (!confirm(`Remove temporary access for ${domain}?`)) return;

    try {
        await window.electronAPI.removeTemporaryAccess(domain, currentToken);
        // Refresh temporary list, blacklist and dashboard so UI reflects the re-blocking immediately
        await loadTemporaryAccess();
        await loadBlacklist();
        await loadDashboard();
    } catch (error) {
        alert('Failed to remove temporary access: ' + error.message);
    }
}

// Load access requests
async function loadAccessRequests() {
    try {
        const requests = await window.electronAPI.getAccessRequests(currentToken);
        const tbody = document.getElementById('requestsBody');
        const isAdmin = currentUser && currentUser.role && currentUser.role.toLowerCase() === 'admin';

        if (!Array.isArray(requests) || requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #94a3b8;">No access requests</td></tr>';
            return;
        }

        const filteredRequests = isAdmin ? requests : requests.filter(req => req.requested_by === currentUser.username);

        if (filteredRequests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #94a3b8;">No access requests</td></tr>';
            return;
        }

        tbody.innerHTML = filteredRequests.map(req => {
            const durationHours = req.requested_duration_minutes ? (req.requested_duration_minutes / 60) : 0;
            return `
                <tr>
                    <td>${req.domain}</td>
                    <td>${req.requested_by}</td>
                    <td>${req.reason || '-'}</td>
                    <td>${req.requested_at ? new Date(req.requested_at).toLocaleString() : '-'}</td>
                    <td>${durationHours ? durationHours + 'h' : 'Temporary'}</td>
                    <td><span class="status-badge badge-${req.status}">${req.status}</span></td>
                    <td>
                        ${req.status === 'pending' && isAdmin ? `
                            <button class="btn btn-success approve-button" data-request-id="${req.id}" data-duration-hours="${durationHours || 24}">Approve</button>
                            <button class="btn btn-danger reject-button" data-request-id="${req.id}">Reject</button>
                        ` : ''}
                    </td>
                </tr>
            `;
        }).join('');
        attachRequestActionHandlers();

    } catch (error) {
        document.getElementById('requestsBody').innerHTML =
            '<tr><td colspan="7" style="text-align: center; color: #ef4444;">Failed to load requests</td></tr>';
    }
}

// Approve request
async function approveRequest(requestId, durationHours) {
    if (!window.electronAPI || !window.electronAPI.approveAccessRequest) {
        alert('Approve action is unavailable. Please reload the app.');
        return;
    }

    try {
        await window.electronAPI.approveAccessRequest(requestId, durationHours, currentToken);
        await loadAccessRequests();
        await loadTemporaryAccess();
        await loadBlacklist();
        await loadDashboard();
        await window.electronAPI.showNotification('Request Approved', 'Access request has been approved');
    } catch (error) {
        alert('Failed to approve request: ' + (error.message || error));
    }
}

function attachRequestActionHandlers() {
    document.querySelectorAll('.approve-button').forEach(button => {
        button.removeEventListener('click', handleApproveButton);
        button.addEventListener('click', handleApproveButton);
    });
    document.querySelectorAll('.reject-button').forEach(button => {
        button.removeEventListener('click', handleRejectButton);
        button.addEventListener('click', handleRejectButton);
    });
}

function handleApproveButton(event) {
    const button = event.currentTarget;
    const requestId = button.dataset.requestId;
    const durationHours = parseFloat(button.dataset.durationHours) || 24;
    if (requestId) {
        approveRequest(Number(requestId), durationHours);
    }
}

function handleRejectButton(event) {
    const button = event.currentTarget;
    const requestId = button.dataset.requestId;
    if (requestId) {
        rejectRequest(Number(requestId));
    }
}

// Reject request
async function rejectRequest(requestId) {
    if (!window.electronAPI || !window.electronAPI.rejectAccessRequest) {
        alert('Reject action is unavailable. Please reload the app.');
        return;
    }

    let reason = prompt('Enter rejection reason:');
    if (reason === null) {
        return;
    }
    reason = reason.trim() || 'No reason provided';
    try {
        await window.electronAPI.rejectAccessRequest(requestId, reason, currentToken);
        await loadAccessRequests();
        await loadDashboard();
        await window.electronAPI.showNotification('Request Rejected', 'Access request has been rejected');
    } catch (error) {
        alert('Failed to reject request: ' + (error.message || error));
    }
}

// Security functions
async function checkPhishing() {
    const url = document.getElementById('phishingUrl').value.trim();
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    try {
        const result = await window.electronAPI.predictPhishing(url, currentToken);
        document.getElementById('securityResults').innerHTML = `
            <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                <h4>Phishing Analysis Result</h4>
                <p><strong>URL:</strong> ${url}</p>
                <p><strong>Phishing Detected:</strong> ${result.is_phishing ? 'Yes' : 'No'}</p>
                <p><strong>Score:</strong> ${(result.score * 100).toFixed(2)}%</p>
                <p><strong>Model Scores:</strong> Char=${(result.char_model * 100).toFixed(2)}%, GRU=${(result.gru_model * 100).toFixed(2)}%</p>
            </div>
        `;
    } catch (error) {
        document.getElementById('securityResults').innerHTML =
            `<div style="color: #ef4444; margin-top: 16px;">Failed to analyze URL: ${error.message}</div>`;
    }
}

async function runNetworkScan() {
    const features = document.getElementById('networkFeatures').value.trim();
    if (!features) {
        alert('Please enter network features');
        return;
    }

    try {
        const parsed = JSON.parse(features);
        const result = await window.electronAPI.predictNetwork(parsed, currentToken);
        document.getElementById('securityResults').innerHTML = `
            <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                <h4>Network Anomaly Analysis</h4>
                <p><strong>Suspicious:</strong> ${result.is_suspicious ? 'Yes' : 'No'}</p>
                <p><strong>Threat Score:</strong> ${(result.score * 100).toFixed(2)}%</p>
                <p><strong>Anomaly Label:</strong> ${result.label_text || result.anomaly_label}</p>
                <p><strong>Threshold:</strong> ${result.threshold}</p>
                <p><strong>Raw Score:</strong> ${result.raw_score}</p>
            </div>
        `;
    } catch (error) {
        document.getElementById('securityResults').innerHTML =
            `<div style="color: #ef4444; margin-top: 16px;">Failed to analyze network: ${error.message}</div>`;
    }
}

async function checkSignature() {
    const content = document.getElementById('signatureInput').value.trim();
    if (!content) {
        alert('Please select a file or enter content to check against signatures');
        return;
    }

    try {
        const result = await window.electronAPI.compareSignature(content, currentToken);
        let resultHtml;
        if (result.matched) {
            resultHtml = `
                <div style="margin-bottom: 8px; padding: 8px; background: rgba(255, 255, 255, 0.05); border-radius: 4px;">
                    <p><strong>Match ID:</strong> ${result.match_id}</p>
                    <p><strong>Description:</strong> ${result.match_description}</p>
                    <p><strong>Similarity Score:</strong> ${(result.score * 100).toFixed(2)}%</p>
                    <p><strong>Known Pattern:</strong> ${result.known_pattern}</p>
                </div>
            `;
        } else {
            resultHtml = '<p><strong>No matching signature found</strong></p>';
        }

        document.getElementById('securityResults').innerHTML = `
            <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                <h4>Signature Matching Results</h4>
                ${resultHtml}
            </div>
        `;
    } catch (error) {
        document.getElementById('securityResults').innerHTML =
            `<div style="color: #ef4444; margin-top: 16px;">Failed to check signature: ${error.message}</div>`;
    }
}

async function selectFileForSignature() {
    try {
        const filePath = await window.electronAPI.selectFile();
        if (filePath) {
            const result = await window.electronAPI.scanFile(filePath, currentToken);
            document.getElementById('signatureInput').value = filePath;
            displaySignatureScanResult(result, filePath, 'file');
        }
    } catch (error) {
        alert('Failed to scan file: ' + error.message);
    }
}

function displaySignatureScanResult(result, pathOrContent, sourceType = 'file') {
    let resultHtml;
    if (sourceType === 'file') {
        if (result.findings && result.findings.length > 0) {
            resultHtml = result.findings.map(match => `
                <div style="margin-bottom: 8px; padding: 8px; background: rgba(255, 255, 255, 0.05); border-radius: 4px;">
                    <p><strong>File:</strong> ${pathOrContent}</p>
                    <p><strong>Signature ID:</strong> ${match.id}</p>
                    <p><strong>Description:</strong> ${match.description}</p>
                    <p><strong>Pattern:</strong> ${match.pattern}</p>
                </div>
            `).join('');
        } else {
            resultHtml = '<p><strong>No matching signatures found in file.</strong></p>';
        }
        document.getElementById('securityResults').innerHTML = `
            <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                <h4>File Signature Scan Results</h4>
                <p><strong>Scanned File:</strong> ${pathOrContent}</p>
                ${resultHtml}
            </div>
        `;
    }
}

async function selectFolderForSignature() {
    try {
        const folderPath = await window.electronAPI.selectDirectory();
        if (folderPath) {
            // Scan folder and get signature matches
            const result = await window.electronAPI.scanFolderSignatures(folderPath, currentToken);
            let matchesHtml = '<p><strong>No matches found in folder</strong></p>';
            if (result.matches && result.matches.length > 0) {
                matchesHtml = result.matches.map(match => `
                    <div style="margin-bottom: 8px; padding: 8px; background: rgba(255, 255, 255, 0.05); border-radius: 4px;">
                        <p><strong>File:</strong> ${match.file_path}</p>
                        <p><strong>Signature:</strong> ${match.signature_id}</p>
                        <p><strong>Description:</strong> ${match.description}</p>
                        <p><strong>Similarity:</strong> ${(match.similarity * 100).toFixed(2)}%</p>
                    </div>
                `).join('');
            }
            document.getElementById('securityResults').innerHTML = `
                <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                    <h4>Folder Signature Scan Results</h4>
                    <p><strong>Scanned Folder:</strong> ${folderPath}</p>
                    ${matchesHtml}
                </div>
            `;
        }
    } catch (error) {
        alert('Failed to scan folder: ' + error.message);
    }
}

async function addToBlacklist() {
    const domain = document.getElementById('blacklistDomain').value.trim();
    if (!domain) {
        alert('Please enter a domain');
        return;
    }

    try {
        await window.electronAPI.addBlacklist(domain, currentToken);
        document.getElementById('blacklistDomain').value = '';
        await window.electronAPI.showNotification('Blacklist Updated', `Domain ${domain} added to blacklist`);
        loadBlacklist();
    } catch (error) {
        alert('Failed to add to blacklist: ' + error.message);
    }
}

async function loadBlacklist() {
    try {
        const tbody = document.getElementById('blacklistBody');
        const isAdmin = currentUser && currentUser.role && currentUser.role.toLowerCase() === 'admin';
        if (!isAdmin) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #94a3b8;">Blacklist access is restricted to administrators.</td></tr>';
            return;
        }

        const [blacklist, temporaryAccess] = await Promise.all([
            window.electronAPI.getBlacklist(currentToken),
            window.electronAPI.getTemporaryAccess(currentToken)
        ]);
        const tempDomains = (Array.isArray(temporaryAccess) ? temporaryAccess : []).map(entry => entry.domain.toLowerCase());

        if (activeBlacklistInterval) {
            clearInterval(activeBlacklistInterval);
            activeBlacklistInterval = null;
        }

        if (!Array.isArray(blacklist) || blacklist.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #94a3b8;">No blacklisted domains</td></tr>';
            // keep refreshing so newly reblocked entries appear if they are added after the page loads
            activeBlacklistInterval = setInterval(loadBlacklist, 5000);
            return;
        }

        tbody.innerHTML = blacklist.map(entry => {
            const lowerDomain = entry.domain.toLowerCase();
            const tempEntry = tempDomains.find(tempDomain => lowerDomain === tempDomain || lowerDomain.endsWith('.' + tempDomain));
            const accessStatus = tempEntry ? '<span class="status-badge badge-success">Temporary access</span>' : '<span class="status-badge badge-danger">Blocked</span>';
            const tempInfo = tempEntry ? `<div style="margin-top: 4px; font-size: 0.85rem; color: #94a3b8;">Authorized temporarily</div>` : '';
            return `
            <tr>
                <td>${entry.domain}${tempInfo}</td>
                <td>${entry.added_by || 'admin'}</td>
                <td>${entry.added_at ? new Date(entry.added_at).toLocaleString() : '-'}</td>
                <td>${accessStatus}</td>
                <td>
                    <button class="btn btn-danger admin-only" onclick="removeFromBlacklist('${entry.domain}')">Remove</button>
                </td>
            </tr>
        `;
        }).join('');

        activeBlacklistInterval = setInterval(loadBlacklist, 5000);
    } catch (error) {
        document.getElementById('blacklistBody').innerHTML =
            '<tr><td colspan="5" style="text-align: center; color: #ef4444;">Failed to load blacklist</td></tr>';
    }
}

function clearBlacklistInterval() {
    if (activeBlacklistInterval) {
        clearInterval(activeBlacklistInterval);
        activeBlacklistInterval = null;
    }
}

async function removeFromBlacklist(domain) {
    if (!confirm(`Remove ${domain} from blacklist?`)) return;

    try {
        await window.electronAPI.removeBlacklist(domain, currentToken);
        loadBlacklist();
        loadDashboard();
        await window.electronAPI.showNotification('Blacklist Updated', `Domain ${domain} removed from blacklist`);
    } catch (error) {
        alert('Failed to remove from blacklist: ' + error.message);
    }
}

async function submitAccessRequest() {
    const domain = document.getElementById('requestDomain').value.trim();
    const reason = document.getElementById('requestReason').value.trim();
    const duration = parseFloat(document.getElementById('requestDuration').value);

    if (!domain) {
        alert('Please enter a domain to request');
        return;
    }

    try {
        await window.electronAPI.requestAccess({
            domain,
            reason,
            requested_duration_minutes: Math.round(duration * 60)
        }, currentToken);
        document.getElementById('requestDomain').value = '';
        document.getElementById('requestReason').value = '';
        loadAccessRequests();
        loadDashboard();
        await window.electronAPI.showNotification('Access Request Sent', `Request for ${domain} was submitted`);
    } catch (error) {
        alert('Failed to submit access request: ' + error.message);
    }
}

async function refreshBlacklist() {
    await loadBlacklist();
}

async function startContinuousNetworkScan() {
    if (networkScanInterval) return; // Already running

    document.getElementById('continuousScanBtn').style.display = 'none';
    document.getElementById('stopScanBtn').style.display = 'inline-block';

    networkScanInterval = setInterval(async () => {
        try {
            const featureResponse = await window.electronAPI.networkFeatures();
            const featureNames = Array.isArray(featureResponse.features) && featureResponse.features.length > 0
                ? featureResponse.features
                : Object.keys(featureResponse.actual || {});

            const features = {};
            featureNames.forEach(name => {
                const value = featureResponse.actual && featureResponse.actual[name] != null
                    ? featureResponse.actual[name]
                    : parseFloat((Math.random() * 100).toFixed(2));
                features[name] = value;
            });

            document.getElementById('networkFeatures').value = JSON.stringify(features, null, 2);
            const result = await window.electronAPI.predictNetwork(features, currentToken);
            const timestamp = new Date().toLocaleTimeString();
            document.getElementById('securityResults').innerHTML = `
                <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                    <h4>Continuous Network Anomaly Analysis</h4>
                    <p><strong>Time:</strong> ${timestamp}</p>
                    <p><strong>Features:</strong></p>
                    <pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(features, null, 2)}</pre>
                    <p><strong>Suspicious:</strong> ${result.is_suspicious ? 'Yes' : 'No'}</p>
                    <p><strong>Threat Score:</strong> ${(result.score * 100).toFixed(2)}%</p>
                    <p><strong>Anomaly Label:</strong> ${result.label_text || result.anomaly_label}</p>
                    <p><strong>Raw Score:</strong> ${result.raw_score}</p>
                    <p><strong>Threshold:</strong> ${result.threshold}</p>
                </div>
            `;
        } catch (error) {
            console.error('Network scan error:', error);
        }
    }, 2000); // Scan every 2 seconds
}

function stopContinuousNetworkScan() {
    if (networkScanInterval) {
        clearInterval(networkScanInterval);
        networkScanInterval = null;
    }

    document.getElementById('continuousScanBtn').style.display = 'inline-block';
    document.getElementById('stopScanBtn').style.display = 'none';

    document.getElementById('securityResults').innerHTML = `
        <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
            <h4>Continuous Network Scan Stopped</h4>
            <p>Scan has been stopped.</p>
        </div>
    `;
}

// Backend status check
async function checkBackendStatus() {
    try {
        const result = await window.electronAPI.backendStatus();
        const statusDiv = document.getElementById('backendStatus');
        if (result.alive) {
            statusDiv.innerHTML = `<span style="color: #22c55e;">✅ ${result.message}</span>`;
        } else {
            statusDiv.innerHTML = `<span style="color: #ef4444;">❌ ${result.message}</span>`;
        }
    } catch (error) {
        document.getElementById('backendStatus').innerHTML =
            '<span style="color: #ef4444;">❌ Failed to check backend status</span>';
    }
}

// Refresh functions
function refreshTemporaryAccess() {
    loadTemporaryAccess();
}

function refreshRequests() {
    loadAccessRequests();
}

// Logout
function logout() {
    currentToken = null;
    currentUser = null;
    document.getElementById('adminDashboard').classList.add('hidden');
    document.getElementById('login').classList.remove('hidden');
    document.getElementById('loginForm').reset();
    document.getElementById('loginError').textContent = '';
}

// Load users
async function loadUsers() {
    try {
        const users = await window.electronAPI.getUsers(currentToken);
        const tbody = document.getElementById('usersBody');

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #94a3b8;">No users found</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => `
            <tr>
                <td>${user.username}</td>
                <td>${user.role}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-danger" onclick="deleteUser(${user.id})">Delete</button>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        document.getElementById('usersBody').innerHTML =
            '<tr><td colspan="4" style="text-align: center; color: #ef4444;">Failed to load users</td></tr>';
    }
}

// Create user
async function createUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value.trim();
    const role = document.getElementById('newRole').value;

    if (!username || !password) {
        alert('Please enter username and password');
        return;
    }

    try {
        await window.electronAPI.createUser({ username, password, role }, currentToken);
        document.getElementById('newUsername').value = '';
        document.getElementById('newPassword').value = '';
        loadUsers();
        await window.electronAPI.showNotification('User Created', `User ${username} created successfully`);
    } catch (error) {
        alert('Failed to create user: ' + error.message);
    }
}

// Delete user
async function deleteUser(userId) {
    if (!confirm(`Delete user?`)) return;

    try {
        await window.electronAPI.deleteUser(userId, currentToken);
        loadUsers();
        await window.electronAPI.showNotification('User Deleted', 'User deleted successfully');
    } catch (error) {
        alert('Failed to delete user: ' + error.message);
    }
}

// Show card details
async function showCardDetails(cardType) {
    switch(cardType) {
        case 'protections':
            // Show blocked domains list
            const blockedDomains = [
                'anydesk.com', 'teamviewer.com', 'logmein.com', 'splashtop.com', 'ultravnc.com',
                'tightvnc.com', 'parsec.app', 'remoteutilities.com', 'ammy.com', 'connectwise.com',
                'screenconnect.com', 'beyondtrust.com', 'kaseya.com'
            ];
            let domainList = blockedDomains.map(domain => `<li>${domain}</li>`).join('');
            document.getElementById('securityResults').innerHTML = `
                <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                    <h4>Blocked RMM Domains</h4>
                    <ul style="list-style-type: disc; margin-left: 20px;">
                        ${domainList}
                    </ul>
                </div>
            `;
            showTab('security');
            break;
        case 'requests':
            showTab('requests');
            break;
        case 'temporary':
            showTab('temporary');
            break;
        case 'system':
            // Show system details
            try {
                const status = await window.electronAPI.getSystemStatus(currentToken);
                document.getElementById('securityResults').innerHTML = `
                    <div style="padding: 16px; border-radius: 8px; background: rgba(255, 255, 255, 0.05); margin-top: 16px;">
                        <h4>System Status Details</h4>
                        <p><strong>Backend Running:</strong> ${status.backend_running ? 'Yes' : 'No'}</p>
                        <p><strong>Proxy Running:</strong> ${status.proxy_running ? 'Yes' : 'No'}</p>
                        <p><strong>Blocked Domains:</strong> ${status.blocked_domains || 0}</p>
                        <p><strong>Temporary Access Entries:</strong> ${status.temporary_unblocks || 0}</p>
                        <p><strong>Pending Requests:</strong> ${status.pending_requests || 0}</p>
                        <p><strong>Uptime:</strong> ${status.uptime_hours || 0} hours</p>
                    </div>
                `;
                showTab('security');
            } catch (error) {
                console.error('Failed to get system details:', error);
            }
            break;
    }
}