# OT Cyber Incident Response Playbook: Industrial Control Systems
**Target Architecture:** Modbus TCP (OpenPLC), Siemens S7comm, Encrypted OPC UA  
**Standard References:** IEC 62443-2-4, IEC 62443-3-3, NIST SP 800-61 Rev. 2, MITRE ATT&CK for ICS  
**Document Classification:** Operational Standard Operating Procedure (SOP)  
**Version:** 1.0 (Production-Ready)

---

## 1. Incident Response Principles in Operational Technology (OT)

In industrial automation environments, cybersecurity incident response differs fundamentally from enterprise IT:

1. **Life Safety & Physical Containment Precede Network Isolation:**  
   Never blindly sever network connections or reboot controllers if doing so impairs safety instrumented systems, disables cooling loops, or leaves pressure vessels unmonitored.
2. **Never Trust Software Feedback During an Active Incident:**  
   If an adversary tampers with PLC memory or poisons SCADA tags, the HMI screen will display nominal conditions while physical equipment is being over-pressurized or drained. **Physical inspection at Level 0 is mandatory.**
3. **Preserve Determinism:**  
   Do not run aggressive vulnerability scanners (e.g., Nmap script scans, Nessus) against active control loops. Doing so can crash legacy TCP/IP stacks and cause emergency shutdowns.

---

## 2. Emergency Operational Matrix

```
+---------------------------------------------------------------------------------------------------+
| THREAT SCENARIO           MITRE ID   INITIAL SYMPTOM                    IMMEDIATE FIRST ACTION    |
+---------------------------------------------------------------------------------------------------+
| Unauthorized Actuator     T0855      Coil forced (%QX0.1 Drain OPEN);   Inspect Level 0 Physical  |
| Manipulation                         Unsolicited valve actuation        Valve; Disconnect Conduit |
+---------------------------------------------------------------------------------------------------+
| Process Parameter         T0836      Holding Register (%QW0) set to     Engage HMI Manual Override|
| Poisoning                            out-of-bounds value (e.g., 9999)   Restore Golden Setpoints  |
+---------------------------------------------------------------------------------------------------+
| Controller CPU Halt       T0805      PLC transitions to STOP mode;      Inspect Physical Keyswitch|
| (Denial of Service)       T0814      Control loop ceases execution      Verify Hardware Interlocks|
+---------------------------------------------------------------------------------------------------+
| Unauthorized Logic        T0843      S7comm Download Block (0x1A/0x1B)  Isolate Engineering Port; |
| Tampering / Program Mod              Checksum mismatch in TIA/OpenPLC   Flash Golden Logic Image  |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Incident Lifecycle Execution Playbook

### Phase 1: Triage & Identification

When the **PlcSentinel OT SOC Dashboard** (`soc_dashboard.py`) or SIEM triggers a `CRITICAL` or `HIGH` alert:

1. **Classify the Protocol & Target Conduit:**
   * **Modbus TCP Alert:** Port `502` / `5020` (Targeting OpenPLC).
   * **Siemens S7comm Alert:** Port `102` / `10200` (Targeting Simatic S7 CPU).
2. **Review Elastic Common Schema (ECS) Alert Evidence:**
   Inspect the live event log (`logs/ot_security_events.jsonl` or `logs/s7_security_events.jsonl`):
   ```bash
   tail -n 5 logs/s7_security_events.jsonl | jq .
   ```
   * Extract: `source.ip`, `modbus.function_code` / `s7comm.function_code`, and `target_item`.

---

### Phase 2: Containment & Remediation by Threat Scenario

#### Scenario A: MITRE ATT&CK T0855 — Unauthorized Command Message (Coil Forcing)

**Mechanism:** Adversary sends Function Code `05` (Write Single Coil) or `15` to manipulate physical actuators (e.g., forcing Drain Valve `%QX0.1` open or shutting off Inflow Pump `%QX0.0`).

* **Step 1 (Physical Level 0 Verification):**  
  Dispatch an operator to inspect the physical valve position indicator. Confirm whether the physical valve opened or if the command was intercepted by the DPI proxy.
* **Step 2 (Conduit Micro-Isolation):**  
  Block the offending source IP at the upstream firewall or Layer-7 gateway:
  ```bash
  # Example Linux Gateway IP Drop:
  iptables -I INPUT -s <OFFENDING_IP> -p tcp --dport 5020 -j DROP
  ```
* **Step 3 (Operational Reversion):**  
  If the actuator was forced before containment, restore safe operational state using the authorized Engineering Workstation:
  ```bash
  .venv/bin/python3 -c "from pymodbus.client import ModbusTcpClient; c = ModbusTcpClient('127.0.0.1', 502); c.connect(); c.write_coil(1, False, device_id=1); c.close()"
  ```

---

#### Scenario B: MITRE ATT&CK T0836 — Modify Parameter / Setpoint Poisoning

**Mechanism:** Adversary injects Function Code `06` (Write Single Register) targeting Holding Register 0 (`%QW0`), altering the high level cutoff from safe `850` (85.0%) to `9999` (999.9%), blinding the controller to overfill conditions.

* **Step 1 (Validate Level 0 Hardwired Interlocks):**  
  Verify that the mechanical float switch (`%IX0.1`) is physically energized. Ensure the hardwired safety relay will de-energize the pump contactor if liquid reaches 95.0%, regardless of PLC register corruption.
* **Step 2 (Engage Manual Supervisory Override):**  
  Assert Manual Mode (`%QX0.3 = TRUE`) to isolate automated logic from poisoned registers.
* **Step 3 (Setpoint Restoration):**  
  Write the certified golden engineering thresholds:
  ```bash
  .venv/bin/python3 -c "from pymodbus.client import ModbusTcpClient; c = ModbusTcpClient('127.0.0.1', 502); c.connect(); c.write_register(0, 850, device_id=1); c.write_register(1, 200, device_id=1); c.close()"
  ```
* **Step 4 (Verify DPI Proxy Policy):**  
  Ensure `modbus_dpi_proxy.py` has the semantic boundary rule active (`max_safe_high_threshold: 900`).

---

#### Scenario C: MITRE ATT&CK T0805 / T0814 — CPU Stop / Controller Denial of Service

**Mechanism:** Adversary injects S7comm Function Code `0x29` (PLC Stop) or floods the ISO-on-TCP stack with malformed COTP packets, forcing the CPU into `S7CpuStatusStop`.

* **Step 1 (Field Verification of Controller State):**  
  Inspect the physical CPU faceplate LEDs:
  * **RUN (Solid Green):** Nominal operation.
  * **STOP (Solid Yellow/Amber):** Execution halted; outputs de-energized to failsafe state.
  * **SF / BF (Flashing Red):** System Fault or Bus Fault.
* **Step 2 (Physical Keyswitch Engagement):**  
  Turn the physical mode selector key on the S7 CPU from `REM` (Remote) to `RUN` (Run-Protected). In `RUN` mode, remote S7comm Stop/Download commands over port 102 are physically locked out by the hardware backplane.
* **Step 3 (Cold / Warm Restart via S7-Sentinel):**  
  Once the offending conduit is isolated, query CPU diagnostic buffer:
  ```bash
  .venv/bin/python3 s7_sentinel.py --port 1102
  ```

---

### Phase 3: Physical Safety Decoupling (Level 0 Audit)

During any active cyber incident, digital telemetry cannot be relied upon as the source of truth. The following hardwired safety mechanisms must be audited on the plant floor:

1. **Mechanical High-Level Float Switches:**  
   Must be physically wired in series with the inflow pump contactor control coil power circuit. When water reaches the high physical float, power must be cut mechanically.
2. **Emergency Stop (E-Stop) Pushbuttons:**  
   Normally Closed (NC) physical circuits must directly de-energize safety relays, completely bypassing the software execution of OpenPLC or Siemens S7.

---

### Phase 4: Forensic Evidence Preservation

Before rebooting controllers or power-cycling gateways, capture forensic evidence in a forensically sound manner:

1. **Preserve ECS Structured Event Streams:**
   Copy all active JSON event logs to write-protected forensic storage:
   ```bash
   cp logs/*.jsonl /forensics/evidence_$(date +%Y%m%d_%H%M%S)/
   sha256sum /forensics/evidence_*/* > /forensics/checksums.txt
   ```
2. **Live Network Traffic Capture (Non-Intrusive PCAP):**
   Capture network traffic on Conduit C-1 without injecting active packets:
   ```bash
   tcpdump -i lo0 -s 0 -w /forensics/incident_conduit_c1.pcap tcp port 502 or tcp port 102 or tcp port 5020 or tcp port 10200
   ```
3. **Controller Memory Dump:**
   Extract raw memory areas (`DB1`, `Area.MK`, and located variables) using [s7_sentinel.py](s7_sentinel.py) and [plc_client.py](plc_client.py) for comparison against golden baseline binaries.

---

### Phase 5: Post-Incident Recovery & IEC 62443 Re-Assessment

1. **Compare Running Logic Against Version-Controlled Golden Baseline:**  
   Compare compiled logic against [tank_control.st](tank_control.st) to verify that rung logic was not modified in memory.
2. **Re-evaluate IEC 62443 Security Levels (SL):**
   * **Target Security Level (SL-T):** SL 2 / SL 3.
   * **Achieved Security Level (SL-A):** Evaluate whether the incident was facilitated by unauthenticated conduits, lack of mutual TLS, or missing Layer-7 DPI filtering.
3. **Hardening Action Items:**
   * Migrate unauthenticated Modbus TCP segments to **OPC UA (IEC 62541)** utilizing `Basic256Sha256` encryption and mutual X.509 certificates.
   * On Siemens controllers, ensure "Permit access with PUT/GET" is restricted strictly to designated Engineering Station IP/MAC addresses.
