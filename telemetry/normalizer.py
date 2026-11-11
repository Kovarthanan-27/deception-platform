import json, time, uuid, os, threading
import forensic_controller
OUT_FILE = "telemetry_events.jsonl"

def emit(data):
    with open(OUT_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")
    print(f"[+] Logged: {data['target_service']} | {data['event_type']} | {data['source_ip']}")

def follow_file(filename):
    """Watches a file for new lines in real-time."""
    if not os.path.exists(filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        open(filename, 'a').close()
    with open(filename, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def parse_cowrie():
    for line in follow_file("../logs/cowrie/cowrie.json"):
        try:
            raw = json.loads(line)
            event_id = raw.get("eventid", "")
            out = {
                "event_id": str(uuid.uuid4()),
                "timestamp": raw.get("timestamp", ""),
                "source_ip": raw.get("src_ip", "Unknown"),
                "target_service": "SSH",
                "target_port": 2222,
                "event_type": "RECON",
                "auth_details": {"username": None, "password": None, "success": False},
                "payload": {"http_method": None, "endpoint": None, "command_executed": None, "raw_input": None}
            }
            if event_id == "cowrie.login.failed":
                out["event_type"] = "AUTH_ATTEMPT"
                out["auth_details"]["username"] = raw.get("username")
                out["auth_details"]["password"] = raw.get("password")
                emit(out)
            elif event_id == "cowrie.command.input":
                out["event_type"] = "COMMAND_EXEC"
                out["payload"]["command_executed"] = raw.get("input")
                emit(out)
            elif event_id == "cowrie.session.connect":
                emit(out)
        except:
            pass

def parse_http():
    for line in follow_file("../logs/http/access.log"):
        try:
            raw = json.loads(line)
            event_type = raw.get("event_type", "RECON")
            out = {
                "event_id": str(uuid.uuid4()),
                "timestamp": raw.get("timestamp", ""),
                "source_ip": raw.get("source_ip", "Unknown"),
                "target_service": "HTTP_IOT",
                "target_port": 8888,
                "event_type": event_type,
                "auth_details": {"username": None, "password": None, "success": False},
                "payload": {
                    "http_method": raw.get("method"),
                    "endpoint": raw.get("endpoint"),
                    "command_executed": None,
                    "raw_input": json.dumps(raw.get("payload", {}))
                }
            }
            emit(out)
            if event_type == "INJECTION_ATTEMPT":
             forensic_controller.acquire_container_forensics("decoy_http")
        except:
            pass
 
def parse_mysql():
    for line in follow_file("../logs/mysql/general.log"):
        line = line.strip()
        if "Connect" in line or "Access denied" in line:
            parts = line.split()
            ip = "Unknown"
            for p in parts:
                if "@" in p:
                    ip = p.split("@")[-1]
            out = {
                "event_id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source_ip": ip,
                "target_service": "MYSQL",
                "target_port": 3307,
                "event_type": "AUTH_ATTEMPT",
                "auth_details": {"username": None, "password": None, "success": False},
                "payload": {"http_method": None, "endpoint": None, "command_executed": None, "raw_input": line}
            }
            emit(out)

if __name__ == "__main__":
    print("[*] Normalizer Engine Started. Listening for attacks...")
    threading.Thread(target=parse_cowrie, daemon=True).start()
    threading.Thread(target=parse_http, daemon=True).start()
    threading.Thread(target=parse_mysql, daemon=True).start()
    
    while True:
        time.sleep(1)