import sys
import os

# Add the project directory to the sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the main scanner script
import vapt_scanner
from flask import Flask, jsonify, request as flask_request, send_from_directory
import threading
import json

# Initialize a standalone Flask app for WSGI / Render
app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))

# Setup global dependencies for the scanner since we bypassed launch_server
vapt_scanner.FLASK_AVAILABLE = True
if not hasattr(vapt_scanner, 'SCAN_STATE'):
    vapt_scanner.SCAN_STATE = {
        "status": "idle", "target": "", "step": "",
        "progress": 0, "total": 0, "current": 0,
        "results_path": None, "error": ""
    }

def _cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

app.after_request(_cors)

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/index.html")
def index_html():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/<path:p>", methods=["OPTIONS"])
def options_handler(p):
    resp = app.make_default_options_response()
    return _cors(resp)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = flask_request.get_json(force=True)
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if vapt_scanner.SCAN_STATE["status"] == "scanning":
        return jsonify({"error": "Scan already in progress"}), 409
    
    vapt_scanner.SCAN_STATE.update({
        "status": "scanning", "target": url, "step": "Starting…",
        "progress": 0, "total": 0, "current": 0,
        "results_path": None, "error": "",
    })
    
    threading.Thread(target=vapt_scanner.run_scan_thread, args=(url, 8765), daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/abort", methods=["POST"])
def api_abort():
    vapt_scanner.SCAN_STATE["status"] = "error"
    vapt_scanner.SCAN_STATE["error"] = "SCAN SEQUENCE ABORTED BY OPERATOR"
    return jsonify({"ok": True})

@app.route("/api/status")
def api_status():
    return jsonify({
        "status":   vapt_scanner.SCAN_STATE["status"],
        "target":   vapt_scanner.SCAN_STATE["target"],
        "step":     vapt_scanner.SCAN_STATE["step"],
        "progress": vapt_scanner.SCAN_STATE["progress"],
        "current":  vapt_scanner.SCAN_STATE["current"],
        "total":    vapt_scanner.SCAN_STATE["total"],
        "error":    vapt_scanner.SCAN_STATE["error"],
    })

@app.route("/api/results")
def api_results():
    rp = vapt_scanner.SCAN_STATE.get("results_path")
    if not rp or not os.path.exists(rp):
        return jsonify({"error": "No results available yet"}), 404
    with open(rp, encoding="utf-8") as f:
        return jsonify(json.load(f))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8765)))
