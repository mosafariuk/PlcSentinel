#!/usr/bin/env python3
"""
PlcSentinel - Automated OpenPLC Program Initializer
Uploads, compiles, and starts the tank_control.st IEC 61131-3 logic on OpenPLC runtime.
"""

import sys
import time
import re
import requests

def init_openplc(base_url="http://127.0.0.1:8081", st_path="tank_control.st", timeout=45):
    s = requests.Session()
    
    # 1. Wait for OpenPLC web server to be reachable
    start_wait = time.time()
    connected = False
    while time.time() - start_wait < timeout:
        try:
            r = s.get(f"{base_url}/login", timeout=3)
            if r.status_code == 200:
                connected = True
                break
        except Exception:
            time.sleep(1)
    
    if not connected:
        print(f"[-] OpenPLC webserver not responding at {base_url}")
        return False

    # 2. Authenticate
    r_login = s.post(f"{base_url}/login", data={"username": "openplc", "password": "openplc"})
    if r_login.status_code != 200:
        print("[-] Login failed.")
        return False

    # Check if already running
    r_dash = s.get(f"{base_url}/dashboard")
    if "Status: <font color = '#02CC07'>Running</font>" in r_dash.text:
        print("[+] OpenPLC runtime is already Running.")
        return True

    # 3. Upload Program
    with open(st_path, "rb") as f:
        r_upload = s.post(f"{base_url}/upload-program", files={"file": (st_path, f, "text/plain")}, data={"submit": "Upload Program"})

    m_file = re.search(r"value=[\x27\"]([^\x27\"]+\.st)[\x27\"]", r_upload.text)
    m_epoch = re.search(r"id=[\x27\"]epoch_time[\x27\"].*?value=[\x27\"](\d+)[\x27\"]", r_upload.text) or \
              re.search(r"value=[\x27\"](\d+)[\x27\"].*?id=[\x27\"]epoch_time[\x27\"]", r_upload.text)

    if not m_file or not m_epoch:
        print("[-] Could not parse upload response.")
        return False

    prog_file = m_file.group(1)
    epoch = m_epoch.group(1)

    s.post(f"{base_url}/upload-program-action", data={
        "prog_name": "TankControl",
        "prog_descr": "Tank Water Level Control Logic",
        "prog_file": prog_file,
        "epoch_time": epoch
    })

    # 4. Compile Program
    s.get(f"{base_url}/compile-program?file={prog_file}")
    compiled = False
    for _ in range(15):
        time.sleep(2)
        logs = s.get(f"{base_url}/compilation-logs").text.strip()
        if "Compilation finished successfully!" in logs:
            compiled = True
            break
        elif "Compilation finished with errors!" in logs:
            print(f"[-] Compilation failed: {logs}")
            return False

    if not compiled:
        print("[-] Compilation timed out.")
        return False

    # 5. Start PLC runtime
    s.get(f"{base_url}/start_plc")
    time.sleep(1)
    r_dash = s.get(f"{base_url}/dashboard")
    if "Running" in r_dash.text:
        print("[+] OpenPLC runtime started and Running successfully!")
        return True
    else:
        print("[-] PLC failed to enter Running state.")
        return False

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081"
    ok = init_openplc(base_url=url)
    sys.exit(0 if ok else 1)
