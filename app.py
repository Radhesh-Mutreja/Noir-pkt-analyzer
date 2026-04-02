from flask import Flask, render_template, request, jsonify, Response
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest, HTTPResponse
from scapy.layers.http import HTTP
import threading
import json
import re
import os
import base64
import datetime
import ipaddress
from collections import defaultdict

app = Flask(__name__)

# ─── Threat Intel (local list + patterns) ───────────────────────────────────
SUSPICIOUS_PORTS = {21, 22, 23, 25, 3389, 4444, 1337, 31337, 8080, 9001}
CRED_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'password=([^&\s]+)',
        r'passwd=([^&\s]+)',
        r'pass=([^&\s]+)',
        r'pwd=([^&\s]+)',
        r'username=([^&\s]+)',
        r'user=([^&\s]+)',
        r'login=([^&\s]+)',
        r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
    ]
]

# Known malicious IP ranges (sample — extend as needed)
KNOWN_BAD_IPS = {
    "198.199.72.101", "185.220.101.45", "45.33.32.156",
    "192.241.207.82", "104.236.198.48"
}

# ─── Global state ────────────────────────────────────────────────────────────
capture_state = {
    "running": False,
    "packets": [],
    "stats": defaultdict(int),
    "thread": None,
}

def classify_packet(pkt):
    result = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": "", "dst": "", "protocol": "OTHER",
        "length": len(pkt),
        "info": "",
        "severity": "normal",
        "flags": [],
    }

    if IP in pkt:
        result["src"] = pkt[IP].src
        result["dst"] = pkt[IP].dst

        # Threat intel check
        if pkt[IP].src in KNOWN_BAD_IPS or pkt[IP].dst in KNOWN_BAD_IPS:
            result["flags"].append("KNOWN_MALICIOUS_IP")
            result["severity"] = "critical"

        # Private IP check
        try:
            if not ipaddress.ip_address(pkt[IP].dst).is_private:
                result["flags"].append("EXTERNAL_TRAFFIC")
        except:
            pass

    if TCP in pkt:
        result["protocol"] = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        result["info"] = f":{sport} → :{dport}"

        if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
            result["flags"].append(f"SUSPICIOUS_PORT_{dport or sport}")
            if result["severity"] == "normal":
                result["severity"] = "warning"

        # HTTP layer
        if pkt.haslayer(HTTPRequest):
            result["protocol"] = "HTTP"
            try:
                method = pkt[HTTPRequest].Method.decode()
                path = pkt[HTTPRequest].Path.decode()
                host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else ""
                result["info"] = f"{method} {host}{path}"
                result["flags"].append("HTTP_REQUEST")

                # Credential sniff in HTTP
                if pkt.haslayer(Raw):
                    raw = pkt[Raw].load.decode(errors="ignore")
                    for pat in CRED_PATTERNS:
                        m = pat.search(raw)
                        if m:
                            result["flags"].append("PLAINTEXT_CREDS")
                            result["severity"] = "critical"
                            result["info"] += f" [CREDS DETECTED]"
                            break
            except:
                pass

        elif pkt.haslayer(HTTPResponse):
            result["protocol"] = "HTTP"
            try:
                code = pkt[HTTPResponse].Status_Code.decode()
                result["info"] = f"HTTP Response {code}"
                result["flags"].append("HTTP_RESPONSE")
            except:
                pass

    elif UDP in pkt:
        result["protocol"] = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        result["info"] = f":{sport} → :{dport}"

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            result["protocol"] = "DNS"
            try:
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                result["info"] = f"Query: {qname}"
                result["flags"].append("DNS_QUERY")
            except:
                pass

    capture_state["stats"][result["protocol"]] += 1
    if result["severity"] == "critical":
        capture_state["stats"]["critical"] += 1
    elif result["severity"] == "warning":
        capture_state["stats"]["warning"] += 1

    return result

def packet_callback(pkt):
    if not capture_state["running"]:
        return
    classified = classify_packet(pkt)
    capture_state["packets"].append(classified)
    if len(capture_state["packets"]) > 1000:
        capture_state["packets"].pop(0)

# ─── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    if capture_state["running"]:
        return jsonify({"status": "already_running"})
    
    data = request.json or {}
    iface = data.get("interface", None)
    
    capture_state["running"] = True
    capture_state["packets"] = []
    capture_state["stats"] = defaultdict(int)

    def run():
        try:
            sniff(iface=iface, prn=packet_callback, store=False,
                  stop_filter=lambda x: not capture_state["running"])
        except Exception as e:
            capture_state["running"] = False

    t = threading.Thread(target=run, daemon=True)
    t.start()
    capture_state["thread"] = t
    return jsonify({"status": "started"})

@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    capture_state["running"] = False
    return jsonify({"status": "stopped", "total": len(capture_state["packets"])})

@app.route("/api/packets")
def get_packets():
    since = int(request.args.get("since", 0))
    packets = capture_state["packets"][since:]
    return jsonify({
        "packets": packets,
        "total": len(capture_state["packets"]),
        "stats": dict(capture_state["stats"]),
        "running": capture_state["running"],
    })

@app.route("/api/upload", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    path = f"/tmp/{f.filename}"
    f.save(path)

    try:
        pkts = rdpcap(path)
        results = []
        stats = defaultdict(int)
        for pkt in pkts[:500]:  # cap at 500
            classified = classify_packet(pkt)
            results.append(classified)
            stats[classified["protocol"]] += 1
            if classified["severity"] == "critical":
                stats["critical"] += 1
            elif classified["severity"] == "warning":
                stats["warning"] += 1

        capture_state["packets"] = results
        capture_state["stats"] = stats

        return jsonify({
            "packets": results,
            "total": len(results),
            "stats": dict(stats),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.remove(path)

@app.route("/api/report")
def generate_report():
    packets = capture_state["packets"]
    stats = dict(capture_state["stats"])
    critical = [p for p in packets if p["severity"] == "critical"]
    warnings = [p for p in packets if p["severity"] == "warning"]

    html = render_template("report.html",
        packets=packets, stats=stats,
        critical=critical, warnings=warnings,
        generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(packets)
    )
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": "attachment;filename=noir_report.html"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)