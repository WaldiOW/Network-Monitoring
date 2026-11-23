import base64
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SUBNET = os.getenv("SCAN_SUBNET", "192.168.1.0/24")
SCAN_TIMES = [t.strip() for t in os.getenv("SCAN_TIMES", "06:00,18:00").split(",") if t.strip()]
RUN_ON_START = os.getenv("RUN_ON_START", "true").lower() == "true"
METRICS_PORT = int(os.getenv("METRICS_PORT", "9200"))
DATA_DIR = os.getenv("DATA_DIR", "/data")
OVERRIDE_FILE = os.path.join(DATA_DIR, "devices.csv")
EXPORT_FILE = os.path.join(DATA_DIR, "network-export.csv")

PRINTER_VENDORS = ("brother", "canon", "epson", "xerox", "kyocera", "ricoh", "lexmark")
MIKROTIK_HOST = os.getenv("MIKROTIK_HOST", "")
MIKROTIK_USER = os.getenv("MIKROTIK_USER", "")
MIKROTIK_PASS = os.getenv("MIKROTIK_PASS", "")
PORTS = "22,80,443,445,631,3389,4343,8443,9100"
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "")

lock = threading.Lock()
devices = {}
last_scan = None


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def load_overrides():
    by_ip = {}
    by_mac = {}
    if not os.path.exists(OVERRIDE_FILE):
        return by_ip, by_mac
    with open(OVERRIDE_FILE, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            entry = {k: (v or "").strip() for k, v in row.items() if k}
            ip = entry.get("ip", "")
            mac = entry.get("mac", "").upper()
            if ip:
                by_ip[ip] = entry
            elif mac:
                by_mac[mac] = entry
    return by_ip, by_mac


def detect_type(ip, name, vendor, ports=frozenset()):
    n = name.lower()
    v = vendor.lower()
    if "aruba" in v or re.match(r"ap[-_]", n) or 4343 in ports:
        return "Access Point"
    if re.search(r"router|fritz|gateway|\bgw\b", n) or ip.endswith(".1"):
        return "Router"
    if re.search(r"switch|\bsw[-_]", n):
        return "Switch"
    if any(p in v for p in PRINTER_VENDORS) or re.search(r"print|drucker", n) or ({9100, 631} & ports and 22 not in ports):
        return "Drucker"
    if re.search(r"laptop|notebook|macbook", n):
        return "Laptop"
    if re.search(r"desktop|\bpc[-_]|rechner", n) or {445, 3389} & ports:
        return "Desktop"
    return "Unbekannt"


def load_leases():
    if not (MIKROTIK_HOST and MIKROTIK_USER and MIKROTIK_PASS):
        return {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"https://{MIKROTIK_HOST}/rest/ip/dhcp-server/lease")
    token = base64.b64encode(f"{MIKROTIK_USER}:{MIKROTIK_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            data = json.load(resp)
    except Exception as e:
        log(f"DHCP-Leases nicht abrufbar: {e}")
        return {}
    result = {}
    for lease in data:
        ip = lease.get("address", "")
        if ip:
            result[ip] = {
                "name": lease.get("host-name", ""),
                "mac": lease.get("mac-address", "").upper(),
            }
    return result


def rest_get(path):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"https://{MIKROTIK_HOST}{path}")
    token = base64.b64encode(f"{MIKROTIK_USER}:{MIKROTIK_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.load(resp)


def load_static_dns():
    if not (MIKROTIK_HOST and MIKROTIK_USER and MIKROTIK_PASS):
        return {}
    try:
        data = rest_get("/rest/ip/dns/static")
    except Exception as e:
        log(f"DNS-Einträge nicht abrufbar: {e}")
        return {}
    return {e["address"]: e["name"] for e in data if e.get("address") and e.get("name")}


def reverse_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except OSError:
        return ""


def snmp_name(ip):
    if not SNMP_COMMUNITY:
        return ""
    try:
        proc = subprocess.run(
            ["snmpget", "-v2c", "-c", SNMP_COMMUNITY, "-Oqv", "-t", "2", "-r", "0", ip, "1.3.6.1.2.1.1.5.0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def port_scan(ips):
    if not ips:
        return {}
    proc = subprocess.run(
        ["nmap", "-Pn", "-T2", "-p", PORTS, "-oX", "-", *ips],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode != 0:
        log(f"Portscan Fehler: {proc.stderr.strip()}")
        return {}
    root = ET.fromstring(proc.stdout)
    result = {}
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        result[addr.get("addr", "")] = {
            int(p.get("portid"))
            for p in host.findall("ports/port")
            if p.find("state") is not None and p.find("state").get("state") == "open"
        }
    return result


def run_scan():
    global last_scan
    proc = subprocess.run(
        ["nmap", "-sn", "-PR", "-T2", "-oX", "-", SUBNET],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode != 0:
        log(f"nmap Fehler: {proc.stderr.strip()}")
        return

    root = ET.fromstring(proc.stdout)
    found = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        hn = host.find("hostnames/hostname")
        name = hn.get("name", "") if hn is not None else ""
        if ip:
            found[ip] = {"name": name, "mac": mac, "vendor": vendor}

    leases = load_leases()
    for ip, lease in leases.items():
        if ip in found:
            found[ip]["name"] = found[ip]["name"] or lease["name"]
            found[ip]["mac"] = found[ip]["mac"] or lease["mac"]

    static_dns = load_static_dns()
    ports = port_scan(list(found))
    for ip in found:
        found[ip]["name"] = found[ip]["name"] or static_dns.get(ip, "") or reverse_name(ip) or snmp_name(ip)
        found[ip]["ports"] = ports.get(ip, set())

    overrides, mac_overrides = load_overrides()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    with lock:
        for ip in devices:
            devices[ip]["up"] = 0

        for ip, d in found.items():
            ov = overrides.get(ip) or mac_overrides.get(d["mac"].upper(), {})
            name = ov.get("name") or d["name"]
            dtype = ov.get("device_type") or detect_type(ip, name, d["vendor"], d["ports"])
            prev = devices.get(ip, {})
            devices[ip] = {
                "name": name,
                "mac": d["mac"] or ov.get("mac", "") or prev.get("mac", ""),
                "vendor": ov.get("vendor") or d["vendor"] or prev.get("vendor", ""),
                "device_type": dtype,
                "up": 1,
                "last_seen": now,
            }

        for ip, ov in overrides.items():
            if ip not in devices:
                devices[ip] = {
                    "name": ov.get("name", ""),
                    "mac": ov.get("mac", ""),
                    "vendor": ov.get("vendor", ""),
                    "device_type": ov.get("device_type") or detect_type(ip, ov.get("name", ""), ""),
                    "up": 0,
                    "last_seen": "-",
                }

        network = ipaddress.ip_network(SUBNET)
        for ip, lease in leases.items():
            if ip in devices or ipaddress.ip_address(ip) not in network:
                continue
            devices[ip] = {
                "name": lease["name"],
                "mac": lease["mac"],
                "vendor": "",
                "device_type": detect_type(ip, lease["name"], "", frozenset()),
                "up": 0,
                "last_seen": "-",
            }

        last_scan = time.time()
        export_csv()

    log(f"Scan fertig: {len(found)} Geräte gefunden, {len(devices)} bekannt")


def export_csv():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(EXPORT_FILE, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Name", "IP-Adresse", "MAC", "Gerätetyp", "Hersteller", "Status", "Zuletzt gesehen"])
        for ip, d in sorted(devices.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
            w.writerow([
                d["name"],
                ip,
                d["mac"],
                d["device_type"],
                d["vendor"],
                "online" if d["up"] else "offline",
                d["last_seen"],
            ])


def esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics_text():
    lines = [
        "# HELP network_device_up 1 wenn Gerät beim letzten Scan erreichbar war",
        "# TYPE network_device_up gauge",
    ]
    info = [
        "# HELP network_device_info Geräteinformationen",
        "# TYPE network_device_info gauge",
    ]
    with lock:
        for ip, d in sorted(devices.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
            labels = (
                f'ip="{esc(ip)}",name="{esc(d["name"])}",mac="{esc(d["mac"])}",'
                f'vendor="{esc(d["vendor"])}",device_type="{esc(d["device_type"])}"'
            )
            info.append(f"network_device_info{{{labels}}} 1")
            lines.append(f'network_device_up{{ip="{esc(ip)}"}} {d["up"]}')
        ts = last_scan or 0
    lines.append("# HELP network_scan_last_timestamp_seconds Zeitpunkt des letzten Scans")
    lines.append("# TYPE network_scan_last_timestamp_seconds gauge")
    lines.append(f"network_scan_last_timestamp_seconds {ts}")
    return "\n".join(lines + info) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = metrics_text().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def safe_scan():
    try:
        run_scan()
    except Exception as e:
        log(f"Scan fehlgeschlagen: {e}")


def next_run(now):
    candidates = []
    for t in SCAN_TIMES:
        h, m = map(int, t.split(":"))
        c = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if c <= now:
            c += timedelta(days=1)
        candidates.append(c)
    return min(candidates)


def scheduler():
    if RUN_ON_START:
        safe_scan()
    while True:
        target = next_run(datetime.now())
        log(f"Nächster Scan: {target:%Y-%m-%d %H:%M}")
        time.sleep(max(0, (target - datetime.now()).total_seconds()))
        safe_scan()


if __name__ == "__main__":
    threading.Thread(target=scheduler, daemon=True).start()
    log(f"Metriken auf Port {METRICS_PORT}, Subnetz {SUBNET}")
    ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), Handler).serve_forever()
