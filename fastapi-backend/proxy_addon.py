from mitmproxy import http, ctx
from urllib.parse import urlparse
import requests
import time
import os

# Hardened ShieldGuard addon
# - consults backend /api/check for every request
# - caches results for 30 seconds
# - injects a block page for blocked domains

BACKEND_CHECK_URL = os.environ.get('SHIELDGUARD_BACKEND_URL', 'http://127.0.0.1:8000')
CHECK_CACHE_TTL = 0  # disabled cache so temporary unblock changes take effect immediately
_check_cache = {}


def normalize_domain(host: str) -> str:
    if not host:
        return ''
    host = host.lower().strip().strip('.')
    if host.startswith('[') and ']' in host:
        host = host.split(']')[-1]
    return host.split(':')[0]


def check_domain(host: str) -> dict:
    now = time.time()
    cached = _check_cache.get(host)
    if cached and now - cached['ts'] < CHECK_CACHE_TTL:
        return cached['result']

    try:
        url = f"{BACKEND_CHECK_URL}/api/check/{host}"
        session = requests.Session()
        session.trust_env = False
        session.proxies = {"http": None, "https": None}
        response = session.get(url, timeout=3)
        if response.status_code == 200:
            result = response.json()
        else:
            result = {"allowed": True}
    except Exception:
        result = {"allowed": True}

    _check_cache[host] = {"ts": now, "result": result}
    return result


class ShieldGuardAddon:
    def __init__(self):
        self.log = ctx.log

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            host = flow.request.host
            if not host:
                host = urlparse(flow.request.pretty_url).hostname or ""
            host = normalize_domain(host)
            if not host:
                return

            backend_host = urlparse(BACKEND_CHECK_URL).hostname
            if host in (backend_host, '127.0.0.1', 'localhost'):
                return

            result = check_domain(host)
            allowed = result.get('allowed', True)
            blacklisted = result.get('blacklisted', False)
            rmm_blocked = result.get('rmm_blocked', False)
            if not allowed:
                self.log.info(f"ShieldGuard: blocking {host} -> allowed={allowed}, blacklisted={blacklisted}, rmm_blocked={rmm_blocked}")
                # Determine if this request is a top-level HTML navigation.
                # Modern browsers send Sec-Fetch-* headers for navigations; fall back to Accept/Upgrade headers.
                headers = {k.lower(): v for k, v in flow.request.headers.items()}
                accept_header = headers.get("accept", "")
                sec_fetch_dest = headers.get("sec-fetch-dest", "")
                sec_fetch_mode = headers.get("sec-fetch-mode", "")
                upgrade_insecure = headers.get("upgrade-insecure-requests", "")
                method = (flow.request.method or "GET").upper()

                is_html_accept = "text/html" in accept_header or "application/xhtml+xml" in accept_header
                is_navigation_fetch = sec_fetch_mode.lower() == "navigate" or sec_fetch_dest.lower() in ("document", "iframe", "frame")
                is_upgrade = upgrade_insecure == "1"
                is_get = method in ("GET", "HEAD")

                is_html_navigation = (is_html_accept and (is_get or is_navigation_fetch or is_upgrade)) or is_navigation_fetch

                if is_html_navigation:
                    # Serve a friendly HTML warning page for top-level navigations
                    flow.response = http.Response.make(
                        200,
                        self._warning_page(host, result),
                        {"Content-Type": "text/html; charset=utf-8"}
                    )
                else:
                    # For subresources / XHR / media requests return a simple 403 so clients fail cleanly
                    flow.response = http.Response.make(
                        403,
                        b"Blocked by ShieldGuard",
                        {"Content-Type": "text/plain; charset=utf-8"}
                    )
        except Exception as e:
            self.log.error(f"ShieldGuardAddon exception: {e}")

    def _warning_page(self, host: str, result: dict) -> str:
        safe_host = (host or "").replace('<', '').replace('>', '')
        reason = 'Blocked by ShieldGuard'
        if result.get('blacklisted'):
            reason = 'Domain is blacklisted'
        elif result.get('rmm_blocked'):
            reason = 'This is a protected RMM domain'
        elif not result.get('allowed'):
            reason = 'Domain is not allowed'
        expires_at = result.get('expires_at')
        expiration_text = f"<p>Whitelist expiry: <strong>{expires_at}</strong></p>" if expires_at else ''
        deep_link = f"{BACKEND_CHECK_URL}/static/blocked.html?domain={host}"
        return f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ShieldGuard — Blocked</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font-family: system-ui, 'Segoe UI', Roboto, Helvetica, Arial; background:#1a1d27; color:#e2e8f0; margin:0;}}
.wrapper{{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#0f1117;}}
.card{{width:100%;max-width:760px;background:#171b2e;border:1px solid rgba(255,255,255,0.06);border-radius:20px;padding:32px;box-shadow:0 20px 80px rgba(0,0,0,.35);}}
h1{{margin:0 0 16px;font-size:28px;color:#f8fafc;}}
p{{margin:0 0 16px;color:#cbd5e1;line-height:1.6;}}
.code{{display:inline-block;padding:8px 12px;background:#111827;border-radius:8px;font-family:monospace;color:#f8fafc;}}
a.button{{display:inline-flex;align-items:center;justify-content:center;padding:14px 22px;margin-top:16px;background:#6366f1;color:#fff;border-radius:12px;text-decoration:none;font-weight:600;}}
.small{{color:#94a3b8;font-size:0.95rem;}}
</style>
</head>
<body>
<div class="wrapper">
  <div class="card">
    <h1>Blocked by ShieldGuard</h1>
    <p>Access to <span class="code">{safe_host}</span> has been blocked.</p>
    <p>{reason}. The connection was intercepted before reaching the destination.</p>
    {expiration_text}
    <p class="small">If you believe this access should be allowed, request approval from your administrator.</p>
    <a class="button" href="{deep_link}">Open access request page</a>
  </div>
</div>
</body>
</html>
"""


addons = [ShieldGuardAddon()]
