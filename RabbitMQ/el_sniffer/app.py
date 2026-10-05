"""
API de control del MITM + sirve el panel web.  SOLO LABORATORIO.

Endpoints:
  GET  /               -> panel (static/index.html)
  GET  /api/status     -> estado completo (on/off, modo, reglas, stats)
  POST /api/attack     -> {"on": true|false}
  POST /api/mode       -> {"mode": "read"|"edit"}
  POST /api/rules      -> {"rules": [{"match": "...", "replace": "..."}]}
  GET  /api/events     -> últimos mensajes vistos/modificados (feed)
"""
import signal
import sys

from flask import Flask, jsonify, request, send_from_directory

from engine import MITMEngine

engine = MITMEngine()
engine.resolve()
engine.start_sniffer()

app = Flask(__name__, static_folder="static", static_url_path="")


@app.after_request
def cors(resp):
    # Permite que un front-end externo (Horizon) consuma la API en el lab.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/status")
def api_status():
    return jsonify(engine.status())


@app.post("/api/attack")
def api_attack():
    on = bool((request.get_json(silent=True) or {}).get("on"))
    engine.start_attack() if on else engine.stop_attack()
    return jsonify(engine.status())


@app.post("/api/mode")
def api_mode():
    mode = (request.get_json(silent=True) or {}).get("mode", "read")
    try:
        engine.set_mode(mode)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(engine.status())


@app.post("/api/rules")
def api_rules():
    rules = (request.get_json(silent=True) or {}).get("rules", [])
    engine.set_rules(rules)
    return jsonify(engine.status())


@app.get("/api/events")
def api_events():
    return jsonify(engine.recent_events())


@app.get("/api/captured")
def api_captured():
    return jsonify(engine.captured_list())


@app.post("/api/replay")
def api_replay():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")
    count = int(data.get("count", 10))
    engine.replay(ids=ids, count=count)
    return jsonify(engine.status())


@app.post("/api/defense/alert")
def api_defense_alert():
    d = request.get_json(silent=True) or {}
    engine.add_alert(d.get("type", "info"), d.get("message", ""))
    return jsonify({"ok": True})


@app.get("/api/defense")
def api_defense():
    return jsonify(engine.defense())


def _shutdown(*_):
    engine.stop_attack()  # restaura las tablas ARP al cerrar
    sys.exit(0)


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


if __name__ == "__main__":
    print("[*] Panel en http://0.0.0.0:8080", flush=True)
    app.run(host="0.0.0.0", port=8080, threaded=True)
