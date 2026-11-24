import os
import subprocess
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = os.environ.get("ARUBA_TARGET", "192.168.1.2")
COMMUNITY = os.environ["ARUBA_COMMUNITY"]
PORT = int(os.environ.get("EXPORTER_PORT", "9118"))
REFRESH_SECONDS = int(os.environ.get("REFRESH_SECONDS", "60"))
CLIENT_AP_MAC_OID = "1.3.6.1.4.1.14823.2.3.3.1.2.5.1.3"
CLIENT_MAC_OID = "1.3.6.1.4.1.14823.2.3.3.1.2.5.1.1"
CLIENT_IP_OID = "1.3.6.1.4.1.14823.2.3.3.1.2.5.1.2"

cache = {"counts": None, "clients": None, "error": None}
cache_lock = threading.Lock()


def walk(oid):
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", COMMUNITY, "-Oqv", "-r", "1", "-t", "20", TARGET, oid],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def hex_to_ap_mac(value):
    digits = value.replace('"', "").strip()
    if digits.lower().startswith("0x"):
        digits = digits[2:]
    return "0x" + "".join(digits.split()).upper()


def hex_to_mac(value):
    return hex_to_ap_mac(value)


def clients_per_ap(ap_values):
    counts = Counter()
    for value in ap_values:
        counts[hex_to_ap_mac(value)] += 1
    return counts


def client_table():
    macs = walk(CLIENT_MAC_OID)
    aps = walk(CLIENT_AP_MAC_OID)
    ips = walk(CLIENT_IP_OID)
    clients = []
    for index, mac in enumerate(macs):
        ap = aps[index] if index < len(aps) else ""
        ip = ips[index] if index < len(ips) else ""
        clients.append({
            "mac": hex_to_mac(mac),
            "ap": hex_to_ap_mac(ap) if ap else "",
            "ip": ip,
        })
    return clients


def refresh_loop():
    while True:
        try:
            ap_values = walk(CLIENT_AP_MAC_OID)
            counts = clients_per_ap(ap_values)
            clients = client_table()
            with cache_lock:
                cache["counts"] = counts
                cache["clients"] = clients
                cache["error"] = None
        except Exception as exc:
            print(f"SNMP-Abfrage fehlgeschlagen: {exc}", flush=True)
            with cache_lock:
                cache["error"] = exc
        time.sleep(REFRESH_SECONDS)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        with cache_lock:
            counts = cache["counts"]
            clients = cache["clients"]
        if counts is None:
            self.send_error(503)
            return
        lines = [
            "# HELP aruba_clients_per_ap Anzahl der Clients je AP aus der Aruba-Client-Tabelle",
            "# TYPE aruba_clients_per_ap gauge",
        ]
        lines += [f'aruba_clients_per_ap{{apMac="{mac}"}} {count}' for mac, count in sorted(counts.items())]
        lines += [
            "# HELP aruba_client_ap Zuordnung Client-MAC zu AP-MAC (Wert 1)",
            "# TYPE aruba_client_ap gauge",
        ]
        lines += [
            f'aruba_client_ap{{clientMac="{c["mac"]}",apMac="{c["ap"]}",clientIp="{c["ip"]}"}} 1'
            for c in (clients or [])
        ]
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    threading.Thread(target=refresh_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
