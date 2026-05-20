#!/usr/bin/env python3
"""
ShieldGuard Unified Launcher
Starts FastAPI backend, sets system proxy, and launches mitmproxy
"""

import subprocess
import sys
import time
import signal
import os
import socket
from pathlib import Path

try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    Fore = Style = type('Mock', (), {'GREEN': '', 'RED': '', 'YELLOW': '', 'BLUE': '', 'RESET': ''})()

def print_colored(message, color=Fore.WHITE):
    """Print colored message if colorama is available"""
    if HAS_COLORAMA:
        print(f"{color}{message}{Style.RESET_ALL}")
    else:
        print(message)


def is_port_in_use(host: str, port: int) -> bool:
    """Return True if a TCP port is already bound on the given host."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if family == socket.AF_INET6:
                    if sock.connect_ex((host, port, 0, 0)) == 0:
                        return True
                else:
                    if sock.connect_ex((host, port)) == 0:
                        return True
        except OSError:
            continue
    return False


def find_process_using_port(port: int):
    """Return a set of process IDs using the given TCP port."""
    pids = set()
    try:
        output = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper().startswith("TCP"):
                local_address = parts[1]
                pid = parts[-1]
                if local_address.endswith(f":{port}"):
                    pids.add(pid)
    except Exception:
        pass
    return pids


def check_dependencies():
    """Check if required dependencies are installed"""
    print_colored("[INFO] Checking dependencies...", Fore.BLUE)

    missing = []
    try:
        import fastapi
    except ImportError:
        missing.append("fastapi")

    try:
        import uvicorn
    except ImportError:
        missing.append("uvicorn")

    try:
        import mitmproxy
    except ImportError:
        missing.append("mitmproxy")

    try:
        import requests
    except ImportError:
        missing.append("requests")

    try:
        import colorama
    except ImportError:
        missing.append("colorama")

    if missing:
        print_colored(f"[ERROR] Missing dependencies: {', '.join(missing)}", Fore.RED)
        print_colored("Run: pip install " + " ".join(missing), Fore.YELLOW)
        return False

    print_colored("[OK] All dependencies installed", Fore.GREEN)
    return True

def start_fastapi():
    """Start FastAPI backend"""
    print_colored("[INFO] Starting FastAPI backend...", Fore.BLUE)
    backend_dir = Path(__file__).parent
    logs_dir = backend_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    fastapi_log = open(logs_dir / "fastapi.log", "a", encoding="utf-8")

    # Start FastAPI through the virtualenv Python interpreter to keep the service in the same process tree.
    cmd = [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"]
    proc = subprocess.Popen(cmd, cwd=backend_dir, stdout=fastapi_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    return proc, fastapi_log


def set_system_proxy():
    """Set Windows system proxy"""
    print_colored("[INFO] Setting system proxy...", Fore.BLUE)
    backend_dir = Path(__file__).parent
    cmd = [sys.executable, "win_proxy.py", "set"]
    result = subprocess.run(cmd, cwd=backend_dir, capture_output=True, text=True)
    if result.returncode == 0:
        print_colored("[OK] System proxy configured", Fore.GREEN)
        return True
    else:
        print_colored(f"[ERROR] Failed to set proxy: {result.stderr}", Fore.RED)
        return False

def start_mitmproxy():
    """Start mitmproxy with addon"""
    print_colored("[INFO] Starting mitmproxy...", Fore.BLUE)
    backend_dir = Path(__file__).parent
    logs_dir = backend_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    mitm_log = open(logs_dir / "mitmproxy.log", "a", encoding="utf-8")

    if is_port_in_use("127.0.0.1", 8080) or is_port_in_use("::1", 8080):
        pids = find_process_using_port(8080)
        details = f" (PID(s): {', '.join(sorted(pids))})" if pids else ""
        print_colored(f"[ERROR] Port 8080 is already in use{details}. Stop any existing proxy or free the port before starting ShieldGuard.", Fore.RED)
        return None, None

    # Prefer mitmdump (non-interactive). Look for venv-installed executable first.
    candidate_paths = []
    exe_name = "mitmdump.exe" if os.name == 'nt' else "mitmdump"
    venv_bin = Path(sys.executable).parent
    candidate_paths.append(venv_bin / exe_name)
    # Some venv layouts place executables in the parent Scripts/ or bin/ folder
    candidate_paths.append(venv_bin / "Scripts" / exe_name)
    candidate_paths.append(venv_bin.parent / "Scripts" / exe_name)
    candidate_paths.append(venv_bin.parent / "bin" / exe_name)

    mitmdump_path = None
    for p in candidate_paths:
        if p.exists():
            mitmdump_path = p
            break

    # Run mitmproxy in dump mode via the venv Python executable to avoid
    # the console-only wrapper behavior on Windows.
    cmd = [sys.executable, "-m", "mitmproxy.tools.dump", "-s", "proxy_addon.py", "--listen-host", "127.0.0.1", "--listen-port", "8080", "--set", "connection_strategy=lazy"]

    print_colored(f"[INFO] Running: {' '.join(cmd)}", Fore.BLUE)

    proc = subprocess.Popen(cmd, cwd=backend_dir, stdout=mitm_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    return proc, mitm_log

def verify_backend_running():
    """Check whether the FastAPI backend is already available."""
    print_colored("[INFO] Checking whether backend is already running...", Fore.YELLOW)
    try:
        import requests
        session = requests.Session()
        session.trust_env = False
        response = session.get("http://127.0.0.1:8000/api/status", timeout=3)
        if response.status_code == 200:
            print_colored("[OK] Backend is already running", Fore.GREEN)
            return True
    except Exception as exc:
        print_colored(f"[WARN] Backend not reachable: {exc}", Fore.YELLOW)
        print_colored("[WARN] Proxy will still start, but blocking/whitelist rules require the backend to be running.", Fore.YELLOW)
        print_colored("Start backend separately with: .\\venv\\Scripts\\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000", Fore.YELLOW)
        return False


def wait_for_backend():
    """Wait for the FastAPI backend to become available."""
    print_colored("[INFO] Waiting for FastAPI backend...", Fore.YELLOW)
    for attempt in range(60):
        try:
            import requests
            response = requests.get("http://127.0.0.1:8000/api/status", timeout=2)
            if response.status_code == 200:
                print_colored("[OK] Backend is running on 127.0.0.1:8000", Fore.GREEN)
                return True
        except Exception:
            pass
        if attempt % 10 == 0:
            print_colored(f"[INFO] Waiting for backend... ({attempt*0.5:.1f}s)", Fore.YELLOW)
        time.sleep(0.5)
    print_colored("[ERROR] Backend did not become available within 30 seconds.", Fore.RED)
    return False


def wait_for_services(mitmproxy_proc):
    """Wait for external services to be ready"""
    print_colored("[INFO] Waiting for mitmproxy to start...", Fore.YELLOW)
    for attempt in range(60):
        if mitmproxy_proc.poll() is not None:
            print_colored(f"[ERROR] Mitmproxy process exited unexpectedly with code {mitmproxy_proc.returncode}", Fore.RED)
            return False

        if is_port_in_use("127.0.0.1", 8080) or is_port_in_use("::1", 8080):
            print_colored("[OK] Mitmproxy is running on 127.0.0.1:8080", Fore.GREEN)
            break

        if attempt % 10 == 0:
            print_colored(f"[INFO] Waiting for mitmproxy... ({attempt*0.5:.1f}s)", Fore.YELLOW)
        time.sleep(0.5)
    else:
        print_colored("[ERROR] Mitmproxy did not open port 8080 within 30 seconds.", Fore.RED)
        return False

    print_colored("[OK] All external services started successfully!", Fore.GREEN)
    return True

def print_startup_info():
    """Print startup information"""
    print_colored("\n" + "="*60, Fore.CYAN)
    print_colored("[SUCCESS] SHIELDGUARD STARTUP COMPLETE", Fore.CYAN)
    print_colored("="*60, Fore.CYAN)
    print_colored("System proxy: 127.0.0.1:8080", Fore.WHITE)
    print_colored("FastAPI API: http://127.0.0.1:8000", Fore.WHITE)
    print_colored("Electron app: Run 'npm start' in front-end/", Fore.WHITE)
    print_colored("", Fore.WHITE)
    print_colored("NEXT STEPS:", Fore.YELLOW)
    print_colored("1. Start the frontend: npm start in front-end/", Fore.WHITE)
    print_colored("2. Open front-end/ and run: npm start", Fore.WHITE)
    print_colored("3. Install mitmproxy CA cert (see README)", Fore.WHITE)
    print_colored("4. Test blocking: Visit anydesk.com", Fore.WHITE)
    print_colored("", Fore.WHITE)
    print_colored("WARNING: Do NOT close this window!", Fore.RED)
    print_colored("Press Ctrl+C to stop all services", Fore.RED)
    print_colored("="*60, Fore.CYAN)

def cleanup():
    """Clean up on exit"""
    print_colored("\n[INFO] Cleaning up...", Fore.YELLOW)

    # Clear system proxy
    backend_dir = Path(__file__).parent
    cmd = [sys.executable, "win_proxy.py", "clear"]
    result = subprocess.run(cmd, cwd=backend_dir, capture_output=True, text=True)
    if result.returncode == 0:
        print_colored("[OK] System proxy cleared", Fore.GREEN)
    else:
        print_colored(f"[ERROR] Failed to clear proxy: {result.stderr}", Fore.RED)

    print_colored("[INFO] ShieldGuard stopped", Fore.BLUE)

def main():
    """Main launcher function"""
    print_colored("[INFO] ShieldGuard Launcher", Fore.CYAN)
    print_colored("="*40, Fore.CYAN)

    # Check dependencies
    if not check_dependencies():
        return 1

    # Check whether the backend is already running
    verify_backend_running()

    processes = []

    try:
        # Start backend if needed
        backend_running = verify_backend_running()
        if not backend_running:
            backend_proc, backend_log = start_fastapi()
            if backend_proc is None:
                return 1
            processes.append(("backend", backend_proc, backend_log))
            if not wait_for_backend():
                return 1
        else:
            print_colored("[INFO] Backend already running, continuing startup.", Fore.GREEN)

        # Set system proxy
        if not set_system_proxy():
            return 1

        # Start mitmproxy
        mitmproxy_proc, mitm_log = start_mitmproxy()
        if mitmproxy_proc is None:
            return 1
        processes.append(("mitmproxy", mitmproxy_proc, mitm_log))

        # Wait for services
        if not wait_for_services(mitmproxy_proc):
            return 1

        # Print info
        print_startup_info()

        # Wait for keyboard interrupt
        def signal_handler(signum, frame):
            print_colored("\n[INFO] Shutdown requested...", Fore.YELLOW)
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        while True:
            time.sleep(1)
            # Check if processes are still running
            for item in processes:
                # item is (name, proc, logfile)
                name, proc, _ = item
                if proc.poll() is not None:
                    print_colored(f"[ERROR] {name} process exited unexpectedly", Fore.RED)
                    return 1

    except KeyboardInterrupt:
        print_colored("\n[INFO] Shutdown requested by user", Fore.YELLOW)
    except Exception as e:
        print_colored(f"[ERROR] Unexpected error: {e}", Fore.RED)
        return 1
    finally:
        # Terminate processes
        for item in processes:
            name, proc, logfile = item
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print_colored(f"[OK] {name} stopped", Fore.GREEN)
            except:
                try:
                    proc.kill()
                    print_colored(f"[WARNING] {name} force killed", Fore.YELLOW)
                except:
                    print_colored(f"[ERROR] Failed to stop {name}", Fore.RED)
            finally:
                try:
                    if logfile and not logfile.closed:
                        logfile.close()
                except:
                    pass

        cleanup()

    return 0

if __name__ == "__main__":
    sys.exit(main())