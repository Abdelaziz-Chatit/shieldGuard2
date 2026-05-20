import winreg
import ctypes
from ctypes import wintypes
from pathlib import Path
import json

# Windows API constants
INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
PROXY_BACKUP_FILE = Path(__file__).resolve().parent / 'proxy_backup.json'

def _read_current_proxy_settings():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_READ)
        proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
        proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0] if proxy_enable else None
        proxy_override = winreg.QueryValueEx(key, "ProxyOverride")[0] if proxy_enable else None
        auto_config_url = None
        try:
            auto_config_url = winreg.QueryValueEx(key, "AutoConfigURL")[0]
        except FileNotFoundError:
            auto_config_url = None
        winreg.CloseKey(key)
        return {
            "ProxyEnable": int(proxy_enable),
            "ProxyServer": proxy_server,
            "ProxyOverride": proxy_override,
            "AutoConfigURL": auto_config_url,
        }
    except Exception:
        return None


def _save_proxy_backup(settings):
    try:
        PROXY_BACKUP_FILE.write_text(json.dumps(settings), encoding='utf-8')
    except Exception as e:
        print(f"[WARNING] Failed to save proxy backup: {e}")


def _load_proxy_backup():
    try:
        if PROXY_BACKUP_FILE.exists():
            return json.loads(PROXY_BACKUP_FILE.read_text(encoding='utf-8'))
    except Exception as e:
        print(f"[WARNING] Failed to read proxy backup: {e}")
    return None


def _apply_proxy_settings(settings):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                         0, winreg.KEY_WRITE)
    if settings is None:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "ProxyServer")
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteValue(key, "ProxyOverride")
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
    else:
        if settings.get("ProxyServer") is not None:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, settings.get("ProxyServer"))
        if settings.get("ProxyOverride") is not None:
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, settings.get("ProxyOverride"))
        if settings.get("AutoConfigURL") is not None:
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, settings.get("AutoConfigURL"))
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(bool(settings.get("ProxyEnable"))))
    winreg.CloseKey(key)
    _refresh_proxy_settings()


def set_system_proxy(host="127.0.0.1", port=8080):
    """Set Windows system proxy to the specified host:port"""
    try:
        current_settings = _read_current_proxy_settings()
        if current_settings is not None:
            _save_proxy_backup(current_settings)

        proxy_server = f"http={host}:{port};https={host}:{port}"
        _apply_proxy_settings({
            "ProxyEnable": 1,
            "ProxyServer": proxy_server,
            "ProxyOverride": "localhost;127.0.0.1;<local>",
            "AutoConfigURL": None,
        })

        print(f"[OK] System proxy set to {proxy_server}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to set system proxy: {e}")
        return False


def clear_system_proxy():
    """Restore original proxy settings or disable proxy."""
    try:
        backup = _load_proxy_backup()
        if backup is not None:
            _apply_proxy_settings(backup)
            try:
                PROXY_BACKUP_FILE.unlink()
            except Exception:
                pass
            print("[OK] System proxy restored to previous settings")
            return True

        _apply_proxy_settings(None)
        print("[OK] System proxy disabled")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to disable system proxy: {e}")
        return False

def _refresh_proxy_settings():
    """Notify Windows that proxy settings have changed"""
    try:
        # Load wininet.dll
        wininet = ctypes.windll.wininet

        # Call InternetSetOption to refresh settings
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)

    except Exception as e:
        print(f"Warning: Could not refresh proxy settings: {e}")

def get_proxy_status():
    """Get current proxy status"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                           0, winreg.KEY_READ)

        proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
        proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0] if proxy_enable else None

        winreg.CloseKey(key)

        return {
            "enabled": proxy_enable == 1,
            "server": proxy_server
        }

    except Exception as e:
        return {"enabled": False, "server": None, "error": str(e)}

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "set":
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
            set_system_proxy(port=port)
        elif command == "clear":
            clear_system_proxy()
        elif command == "status":
            status = get_proxy_status()
            print(f"Proxy enabled: {status['enabled']}")
            print(f"Proxy server: {status['server']}")
        else:
            print("Usage: python win_proxy.py [set|clear|status] [port]")
    else:
        # Default: set proxy
        set_system_proxy()