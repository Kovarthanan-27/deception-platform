from flask import Flask, request, jsonify
import datetime, json, os

app = Flask(__name__)
LOG_FILE = "/logs/http/access.log"

PATIENT_DB = [
    {"patient_id": "PT-9021", "device": "Cardiac-Monitor-V3", "heart_rate": 82, "spo2": 98, "status": "STABLE"},
    {"patient_id": "PT-4412", "device": "Neuro-Stress-Band", "heart_rate": 115, "spo2": 94, "status": "ELEVATED_STRESS"}
]

def log_event(event_type, payload):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_ip": request.remote_addr,
        "method": request.method,
        "endpoint": request.path,
        "event_type": event_type,
        "payload": payload
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

@app.route("/", methods=["GET"])
def index():
    log_event("RECON", {"msg": "IoT Gateway Probe"})
    return jsonify({"service": "MedTech IoT Gateway", "api_version": "v1.4", "status": "active"}), 200

@app.route("/api/v1/patient/telemetry", methods=["GET", "POST"])
def telemetry():
    if request.method == "POST":
        data = request.form.to_dict() or request.get_json(silent=True) or {}
        raw = json.dumps(data)
        if any(char in raw for char in ["'", "\"", "--", ";", "UNION", "cat", "wget", "curl"]):
            log_event("INJECTION_ATTEMPT", {"input": data})
            return jsonify({"error": "Malformed payload", "status": "flagged"}), 400
        log_event("DATA_INGEST", {"input": data})
        return jsonify({"status": "acknowledged"}), 201
    
    log_event("DATA_QUERY", {"params": request.args.to_dict()})
    return jsonify({"patients": PATIENT_DB}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)