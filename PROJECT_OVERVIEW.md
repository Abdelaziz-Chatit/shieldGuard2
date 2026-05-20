# ShieldGuard — Project Overview

## Summary
ShieldGuard is a local network protection suite that detects phishing URLs, inspects network traffic for anomalies, and blocks known remote-management (RMM) or malicious domains via an HTTP proxy. It consists of a FastAPI backend providing detection APIs and a browser/Electron front-end for management and viewing alerts. The system uses a mitmproxy-based interception layer to apply blocking decisions in real time.

## Goals
- Detect and label phishing URLs using ensemble deep-learning models.
- Identify anomalous network traffic using an isolation-forest model.
- Enforce blocking via a local mitmproxy instance and a Windows system proxy.
- Provide an admin UI for whitelisting, blacklisting, and access requests.

## Repository Structure (key items)
- `fastapi-backend/` — Backend API and services
  - `app.py` — Main FastAPI application and API endpoints (phishing prediction, network prediction, whitelist/blacklist, proxy-check API, admin endpoints)
  - `start.py` — Launcher which starts the backend, sets system proxy, and launches `mitmdump` (mitmproxy)
  - `proxy_addon.py` — mitmproxy addon used to check domains and inject block page
  - `win_proxy.py` — Windows proxy helper script (set/clear system proxy)
  - `models/` — ML models (char_cnn, cnn_gru, isolation_forest and related artifact files)
  - `signatures/` — Known signature database and IoC text lists
  - `.env` — configuration values (thresholds, model paths)
  - `logs/` — runtime logs
- `front-end/` — Electron application for the administration UI
  - `main.js`, `renderer.js`, `preload.js`, `index.html` — UI and IPC handlers to backend
- `browser-extension/` — Lightweight extension that can interact with the proxy or UI (optional)
- `static/` — Static files served by the backend (blocked page template)
- `user_data/` — Runtime user and cache data for Electron app (local only)

## Architecture and Data Flow
1. User or system traffic flows through the system proxy (127.0.0.1:8080). Mitmproxy (`mitmdump`) intercepts requests.
2. `proxy_addon.py` extracts the requested hostname, checks the local whitelist and a set of built-in RMM-blocked domains.
3. For undecided domains, the addon queries the backend API endpoint `/api/check/{domain}`. The backend consults the whitelist/blacklist DB and returns a decision.
4. If blocked, mitmproxy returns a friendly `blocked.html` page (served from `static/blocked.html`) to the client; otherwise, the request is allowed to proceed.
5. The front-end (Electron) communicates with the backend over HTTP for management operations, model runs (`/predict_phishing`, `/predict_network`), and status.

## Detection Components
- Phishing detection (`/predict_phishing`): ensemble of two models — `char_cnn` and `cnn_gru` — their output scores are averaged and clipped to [0,1]. The project threshold for labeling phishing is now set to **0.4** (was previously 0.5).
- Network anomaly detection (`/predict_network`): isolation-forest model is used; default threshold set in `.env` (e.g., `THREAT_THRESHOLD_IF=0.6161`).
- Signature matching: known signatures are loaded from `signatures/known_signatures.json` and `signatures/iocs/*.txt` for hash/name/pattern based matching.

## Configuration
Primary configuration is in `fastapi-backend/.env`. Important variables:
- `API_PORT` — configured API port (default used by project: 8000 in practice)
- `THREAT_THRESHOLD_URL` — phishing threshold (now `0.4`)
- `THREAT_THRESHOLD_NETWORK` — default network threshold
- Model paths: `CHAR_CNN_MODEL_PATH`, `CNN_GRU_MODEL_PATH`, `IF_MODEL_PATH`, etc.

## How to Run (development)
Prerequisites: Python 3.8+, a virtualenv, Node.js for the front-end (if running Electron). Mitmproxy (installed in the virtualenv) is required for proxy functionality.

1. Create and activate virtualenv, install Python deps (example):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r fastapi-backend/requirements.txt  # if present
pip install fastapi uvicorn mitmproxy requests keras tensorflow scikit-learn sqlalchemy
```

2. Start backend and proxy (development quick-start):

```powershell
# Start backend (from fastapi-backend/)
cd fastapi-backend
# Option A: use launcher (starts backend + mitmdump + sets proxy)
.\venv\Scripts\python.exe start.py
# Option B: run uvicorn directly (for debugging)
.\venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
# Start mitmproxy separately (if not using launcher):
.\venv\Scripts\mitmdump.exe -s proxy_addon.py --listen-port 8080
# Set system proxy (Windows):
.\venv\Scripts\python.exe win_proxy.py set
```

3. Run the Electron front-end (optional):

```powershell
cd front-end
npm install
npm start
```

## Testing Endpoints
- Phishing prediction (POST):

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict_phishing -Method Post -Body (ConvertTo-Json @{ url = 'https://example.com' }) -ContentType 'application/json'
```

- Proxy check (GET):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/check/example.com
```

- Whitelist fetch (GET):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/whitelist
```

## Recent Fixes / Known Issues
- Fixed: Launcher (`start.py`) detach behavior on Windows by invoking the backend with the same `python` interpreter (helps keep process handles).
- Fixed: Proxy blocking everything due to strict handling — `proxy_addon.py` now normalizes hostnames, strips ports, and fails open on API errors.
- Changed: Phishing threshold lowered from `0.5` to `0.4` in `fastapi-backend/app.py` and `.env`.
- Known: Port conflicts (e.g., `WinError 10013`) can occur if stale Python/uvicorn/mitmdump processes remain — stop stale processes before starting launcher.

## Security Notes
- Models loaded from disk should be validated for version compatibility. Some warnings about sklearn model versions are present when running.
- The system relies on mitmproxy TLS interception; to inspect HTTPS traffic properly you must install the mitmproxy CA certificate on clients.

## Recommended Next Steps for Report
- Include high-level deployment architecture (diagram: client → system proxy → mitmproxy → backend DB).
- Add test vectors that demonstrate phishing labeling: sample URLs and resulting scores before/after threshold change.
- Document administrative actions (whitelist flow, access requests, and log retention policy).

## Contact / Maintainers
The repository root contains the main launcher and front-end. For follow-ups, inspect these files:
- `fastapi-backend/app.py`
- `fastapi-backend/start.py`
- `fastapi-backend/proxy_addon.py`
- `front-end/renderer.js` and `front-end/main.js`

---
*Generated on May 15, 2026 — adjust commands/paths to your environment before running.*
