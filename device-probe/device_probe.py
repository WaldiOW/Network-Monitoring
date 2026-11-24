import csv
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGETS_FILE = os.environ.get("TARGETS_FILE", "/config/targets.csv")
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9300"))
PROBE_INTERVAL = float(os.environ.get("PROBE_INTERVAL", "1"))
PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", "1"))

cache = {}
cache_lock = threading.Lock()


def load_targets():
    with open(TARGETS_FILE, newline="", encoding="utf-8") as f:
        return [
            {"name": r["name"].strip(), "ip": r["ip"].strip(), "subnet": r.get("subnet", "").strip()}
            for r in csv.DictReader(f)
            if r.get("ip")
        ]


def ping(target):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT), target["ip"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT + 2,
        )
        up = 1 if result.returncode == 0 else 0
    except subprocess.TimeoutExpired:
        up = 0
    return target, up


def refresh_loop():
    targets = load_targets()
    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
        while True:
            started = time.time()
            for target, up in pool.map(ping, targets):
                key = (target["name"], target["ip"], target["subnet"])
                with cache_lock:
                    cache[key] = up
            time.sleep(max(0.0, PROBE_INTERVAL - (time.time() - started)))


def esc(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def render_metrics():
    lines = [
        "# HELP device_up Erreichbarkeit per Ping (1 = online, 0 = offline)",
        "# TYPE device_up gauge",
    ]
    with cache_lock:
        items = list(cache.items())
    for (name, ip, subnet), up in sorted(items):
        lines.append(f'device_up{{name="{esc(name)}",ip="{esc(ip)}",subnet="{esc(subnet)}"}} {up}')
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = render_metrics().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    threading.Thread(target=refresh_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), Handler).serve_forever()
