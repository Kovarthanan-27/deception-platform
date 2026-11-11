import subprocess, json, os, time, datetime

EVIDENCE_DIR = "./forensic_evidence"

def execute_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def acquire_container_forensics(container_name="decoy_http", incident_id=None):
    if not incident_id:
        incident_id = f"INC-{int(time.time())}"
    
    incident_path = os.path.join(EVIDENCE_DIR, incident_id)
    os.makedirs(incident_path, exist_ok=True)
    print(f"\n[!] CRITICAL EVENT TRIGGERED: Initiating Forensics on {container_name}")
    start_time = time.time()

    execute_cmd(f"docker pause {container_name}")
    print(f"[*] Step 1: Container '{container_name}' successfully PAUSED.")

    inspect_json = execute_cmd(f"docker inspect {container_name}")
    with open(f"{incident_path}/container_inspect.json", "w") as f:
        f.write(inspect_json)

    top_output = execute_cmd(f"docker top {container_name} aux")
    with open(f"{incident_path}/process_list.txt", "w") as f:
        f.write(top_output)

    diff_output = execute_cmd(f"docker diff {container_name}")
    with open(f"{incident_path}/filesystem_diff.txt", "w") as f:
        f.write(diff_output)

    archive_path = f"{incident_path}/fs_snapshot.tar"
    execute_cmd(f"docker export {container_name} -o {archive_path}")

    execute_cmd(f"docker unpause {container_name}")

    elapsed = round(time.time() - start_time, 2)
    metadata = {
        "incident_id": incident_id,
        "target_container": container_name,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "acquisition_latency_sec": elapsed
    }
    with open(f"{incident_path}/metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"[+] Forensic Acquisition Complete in {elapsed}s. Artifacts in {incident_path}\n")
    return incident_path

if __name__ == "__main__":
    acquire_container_forensics("decoy_http", "TEST-INCIDENT-001")