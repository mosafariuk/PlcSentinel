# 7-Day Hands-On ICS/OT Security Lab Guide: OpenPLC & Wireshark

**Target Audience:** ICS/OT Security Engineers, SOC Analysts, Penetration Testers, Automation Engineers  
**Focus Protocols:** Modbus TCP (Port 502), IEC 61131-3 Logic Execution  
**Standard Reference:** IEC 62443 (ISA/IEC 62443-3-2, 62443-3-3, 62443-4-2), Purdue Enterprise Reference Architecture (PERA)

---

## 7-Day Experiment Roadmap Overview

| Day | Focus Area | Deliverables & Milestones |
| :--- | :--- | :--- |
| **Day 1** | **Environment & Architecture** | Deploy OpenPLC runtime via Docker; install OpenPLC Editor; verify Web GUI on port 8080 and Modbus on port 502. |
| **Day 2** | **PLC Logic Programming** | Write and compile IEC 61131-3 logic (Structured Text / Ladder); map variables to Modbus memory table (`%IX`, `%QX`, `%IW`, `%QW`). |
| **Day 3** | **Modbus TCP Protocol Dissection** | Set up Wireshark on loopback interface; capture normal polling cycles; dissect MBAP Header & PDU structures. |
| **Day 4** | **Automation with `pymodbus`** | Build a secure Python client for state polling, input validation, and telemetry logging; execute controlled write commands. |
| **Day 5** | **Attack Surface & OT Anomaly Analysis** | Replay commands, test unauthorized register write injections, simulate coil flipping, and inspect PLC fault modes. |
| **Day 6** | **OT Detection & Telemetry Rules** | Formulate Wireshark display filters; create Suricata/Snort detection signatures for abnormal Modbus Function Codes and out-of-range payloads. |
| **Day 7** | **IEC 62443 Hardening & Defenses** | Apply Zones & Conduits segmentation; implement Modbus Deep Packet Inspection (DPI) firewall policies; document threat matrix. |

---

## 1. Prerequisites & Environment Setup

### 1.1 Architecture & Components

```
+--------------------------------------------------------------------------+
| HOST WORKSTATION (Isolated Lab Environment)                              |
|                                                                          |
|  +-----------------------------+         +----------------------------+  |
|  | Engineering Workstation     |         | OT Security Analyst        |  |
|  | - OpenPLC Editor (ST / LD)  |         | - Wireshark (Port 502)     |  |
|  | - Python 3 + pymodbus       |         | - Modbus Packet Dissector  |  |
|  +--------------+--------------+         +--------------+-------------+  |
|                 | (Modbus TCP / Loopback 127.0.0.1)     |                |
|                 +-----------------------+---------------+                |
|                                         |                                |
|                        +----------------v----------------+               |
|                        | OpenPLC v3 Runtime (Docker)     |               |
|                        | - Modbus Server: Port 502/TCP   |               |
|                        | - Web Management: Port 8080/TCP |               |
|                        | - Virtual I/O Process Memory    |               |
|                        +---------------------------------+               |
+--------------------------------------------------------------------------+
```

### 1.2 OpenPLC Runtime Deployment (Docker)

Using Docker guarantees an isolated sandbox without polluting your host system libraries.

```bash
# Pull and start the official OpenPLC v3 container
docker run -d \
  --name openplc-sandbox \
  -p 8080:8080 \
  -p 502:502 \
  --restart unless-stopped \
  thiagoralves/openplc:v3
```

- **Web Dashboard:** Navigate to `http://localhost:8080`
- **Default Credentials:** Username: `openplc` | Password: `openplc`
- **Immediate Task:** Change default administrative password in **Settings** to align with IEC 62443-4-2 (FR 1 - Identification and Authentication Control).

### 1.3 OpenPLC Editor Installation
1. Download OpenPLC Editor for your operating system (macOS / Linux / Windows) from [openplcproject.com](https://openplcproject.com).
2. The Editor supports all 5 IEC 61131-3 programming languages:
   - **Ladder Diagram (LD)**
   - **Structured Text (ST)**
   - **Function Block Diagram (FBD)**
   - **Instruction List (IL)**
   - **Sequential Function Chart (SFC)**

### 1.4 Control Logic: Tank Level Water System with Safety Interlocks
In industrial plants, level control systems must prevent tank overfills (loss of containment) and pump cavitations (dry running).

Below is the Structured Text program (`tank_control.st`):

```iecst
PROGRAM TankLevelControl
  VAR
    LowLevelSensor AT %IX0.0 : BOOL;      (* Digital Input: Float switch at low limit *)
    HighLevelSensor AT %IX0.1 : BOOL;     (* Digital Input: Float switch at high limit *)
    EmergencyStop AT %IX0.2 : BOOL;       (* Digital Input: Physical E-Stop contact *)
    
    PumpMotor AT %QX0.0 : BOOL;           (* Digital Output: Inflow pump *)
    DrainValve AT %QX0.1 : BOOL;          (* Digital Output: Emergency drain valve *)
    AlarmBeacon AT %QX0.2 : BOOL;         (* Digital Output: Critical high alarm *)

    TankLevelRaw AT %IW0 : UINT;          (* Input Register: Scaled 0-1000 (0.0% - 100.0%) *)
    HighThreshold AT %QW0 : UINT := 850;  (* Holding Register: Max setpoint (85.0%) *)
    LowThreshold AT %QW1 : UINT := 200;   (* Holding Register: Min setpoint (20.0%) *)
    ManualOverride AT %QX0.3 : BOOL;      (* Digital Output: Remote HMI override *)
  END_VAR

  (* Failsafe Interlock: E-Stop or Overfill triggers immediate pump shutdown *)
  IF NOT EmergencyStop OR (TankLevelRaw >= HighThreshold) THEN
    PumpMotor := FALSE;
    AlarmBeacon := (TankLevelRaw >= HighThreshold);
  ELSIF (TankLevelRaw <= LowThreshold) AND NOT ManualOverride THEN
    PumpMotor := TRUE;
    AlarmBeacon := FALSE;
  END_IF;

  (* Protection against catastrophic containment breach *)
  IF HighLevelSensor OR (TankLevelRaw >= 950) THEN
    DrainValve := TRUE;
    AlarmBeacon := TRUE;
  ELSE
    DrainValve := FALSE;
  END_IF;
END_PROGRAM
```

### 1.5 OpenPLC Memory Table Mapping

| IEC 61131-3 Address | Modbus Object Type | Modbus Function Code (Read/Write) | Modbus Zero-Based Offset | Description |
| :--- | :--- | :--- | :--- | :--- |
| `%IX0.0` - `%IX0.7` | Discrete Input | FC 02 (Read Discrete Inputs) | `0` - `7` | Digital Sensors (Low/High/E-Stop) |
| `%QX0.0` - `%QX0.7` | Coil (Discrete Output) | FC 01 (Read), FC 05 (Write Single), FC 15 (Write Multiple) | `0` - `7` | Actuators (Pump, Drain, Alarm) |
| `%IW0` - `%IW7` | Input Register | FC 04 (Read Input Registers) | `0` - `7` | Analog Inputs (Water Level Sensor) |
| `%QW0` - `%QW7` | Holding Register | FC 03 (Read), FC 06 (Write Single), FC 16 (Write Multiple) | `0` - `7` | Setpoints (High/Low Thresholds) |

---

## 2. Protocol Analysis & Inspection with Wireshark

### 2.1 Packet Capture Setup
- **Interface Selection:**
  - **macOS:** `Loopback: lo0`
  - **Linux:** `Loopback: lo`
  - **Windows:** `Npcap Loopback Adapter`
- **Capture Filter (pre-capture):** `tcp port 502`

### 2.2 Anatomical Breakdown of Modbus TCP Frame

Modbus TCP strips the CRC checksum from Modbus RTU and encapsulates the application PDU into an **MBAP (Modbus Application Protocol)** Header:

```
+--------------------------------------------------------------------------------+
| Ethernet Header | IPv4 Header | TCP Header (Dst Port 502)                      |
+--------------------------------------------------------------------------------+
| MBAP Header (7 Bytes)                                                          |
|  - Transaction Identifier : 2 Bytes (Matches request and response)             |
|  - Protocol Identifier    : 2 Bytes (Always 0x0000 for Modbus)                 |
|  - Length Field           : 2 Bytes (Remaining byte count: Unit ID + PDU)      |
|  - Unit Identifier (Slave): 1 Byte  (Device address, default 0x01)             |
+--------------------------------------------------------------------------------+
| Modbus PDU (Variable)                                                          |
|  - Function Code          : 1 Byte  (e.g., 0x01, 0x03, 0x05, 0x06, 0x10)       |
|  - Data Payload           : N Bytes (Address, Count, Register values)          |
+--------------------------------------------------------------------------------+
```

### 2.3 Wireshark Display Filters Cheat Sheet

| Purpose | Wireshark Display Filter |
| :--- | :--- |
| **All Modbus Traffic** | `mbtcp` |
| **Read Coils (FC 01)** | `modbus.func_code == 1` |
| **Read Discrete Inputs (FC 02)**| `modbus.func_code == 2` |
| **Read Holding Registers (FC 03)**| `modbus.func_code == 3` |
| **Read Input Registers (FC 04)**| `modbus.func_code == 4` |
| **Write Single Coil (FC 05)** | `modbus.func_code == 5` |
| **Write Single Register (FC 06)**| `modbus.func_code == 6` |
| **Write Multiple Coils (FC 15)**| `modbus.func_code == 15` |
| **Write Multiple Registers (FC 16)**| `modbus.func_code == 16` |
| **Modbus Exception Responses**| `modbus.exception_code` or `modbus.func_code >= 128` |
| **Target Specific Register Address**| `modbus.reference_num == 0` |
| **Suspicious Out-of-Range Payloads**| `modbus.data_value > 900` |
| **Non-Standard Unit IDs** | `mbtcp.unit_id != 1` |

---

## 3. Logic Verification & Automation (`pymodbus`)

The Python automation script `plc_client.py` provides non-destructive telemetry polling and controlled testing.

### 3.1 Installation
```bash
pip install pymodbus
```

### 3.2 Key Testing Procedures
1. **Telemetry Polling:** Verify that digital coils (`%QX0.0` - `%QX0.3`) and analog holding registers (`%QW0` - `%QW1`) correspond to runtime states.
2. **Boundary Testing:** Attempt writing valid setpoints (`High=850`, `Low=200`) and verify via Wireshark that an FC 06 packet is issued and an identical echo response is returned.
3. **Negative / Exception Testing:** Request registers beyond the configured allocation (e.g., address `9999`) to observe **Modbus Exception Code 0x02 (Illegal Data Address)** in Wireshark.

---

## 4. Defensive Hardening & IEC 62443 Alignment

Modbus TCP is an inherently unauthenticated, unencrypted, cleartext protocol with no native integrity verification. Anyone with IP-level access can manipulate coils, override safety thresholds, and read process telemetry.

### 4.1 Purdue Reference Architecture & Network Segmentation

```
+-------------------------------------------------------------------+
| Enterprise Zone (Level 4/5) - ERP, Cloud, Corporate Networks      |
+-------------------------------------------------------------------+
                                || [Firewall / DMZ - Level 3.5]
+-------------------------------------------------------------------+
| Operations DMZ (Level 3.5) - Historian Mirror, Patch Repositories |
+-------------------------------------------------------------------+
                                || [OT Perimeter Firewall]
+-------------------------------------------------------------------+
| Operations & Supervisory Zone (Level 3) - SCADA Server, Historian |
+-------------------------------------------------------------------+
                                || [Internal Conduit / OT IDS]
+-------------------------------------------------------------------+
| Control Zone (Level 2) - HMIs, Engineering Workstations (EWS)     |
+-------------------------------------------------------------------+
                                || [Conduit: DPI Firewall / Micro-seg]
+-------------------------------------------------------------------+
| Basic Control Zone (Level 1) - OpenPLC, Safety Instrumented Systems|
+-------------------------------------------------------------------+
                                || [Fieldbus / Hardwired I/O]
+-------------------------------------------------------------------+
| Process Zone (Level 0) - Pumps, Valves, Float Sensors             |
+-------------------------------------------------------------------+
```

### 4.2 IEC 62443 Security Levels (SL) Applied

| Level | Definition | Technical Requirements Applied to PLC Setup |
| :--- | :--- | :--- |
| **SL 1** | Protection against casual or coincidental violation | Change default Web GUI credentials; enable local OS firewall; disable unused services (SSH, Telnet, HTTP). |
| **SL 2** | Protection against intentional violation using simple means | Zone & Conduit segmentation; enforce Deep Packet Inspection (DPI) to block Write function codes from non-authorized IPs. |
| **SL 3** | Protection against intentional violation using sophisticated means | Mutual TLS / IPsec tunneling between SCADA Master and PLC (Modbus Security - IEC 62443-4-2); firmware code signing. |
| **SL 4** | Protection against state-sponsored / high-capability actors | Hardwired physical safety interlocks (SIS) completely decoupled from IP networks; out-of-band behavioral monitoring. |

### 4.3 Practical Hardening Matrix

1. **Conduit Enforcement via Modbus DPI (Deep Packet Inspection):**
   - In production OT firewalls (e.g., Fortinet, Palo Alto, Cisco ISA, or open-source Suricata/iptables), configure rules such that:
     - **HMI / SCADA IP:** Allowed only `FC 01, 02, 03, 04` (Read operations).
     - **Engineering Workstation (EWS) IP:** Permitted `FC 05, 06, 15, 16` during approved change windows only.
     - **All other IPs:** Denied and logged.

2. **Network Host Restrictions (Docker / Linux):**
   ```bash
   # Bind OpenPLC only to a dedicated management interface or localhost
   # Avoid 0.0.0.0 binding in production environments
   docker run -d -p 127.0.0.1:8080:8080 -p 127.0.0.1:502:502 ...
   ```

3. **Engineering Logic Protections:**
   - Always implement physical hardware interlocks (Level 0/1) for catastrophic failure modes (over-pressure release valves, hardwired E-stop circuits). Software logic should never be the sole line of defense against physical destruction.

---

## 5. Advanced Active Defense: Inline Layer-7 Modbus DPI Proxy

To advance beyond passive detection, the laboratory includes an inline Deep Packet Inspection proxy ([modbus_dpi_proxy.py](file:///Users/mo/Articles/PlcSentinel/modbus_dpi_proxy.py)) listening on port `5020` and protecting OpenPLC on port `502`:

```
+------------------+         +-------------------------------+         +-----------------------+
| Untrusted Client | ------> | Modbus L7 DPI Proxy (:5020)   | ------> | OpenPLC Runtime (:502)|
| or HMI Station   | <------ | - Rule 1: IP / FC Whitelist   | <------ | - Protected Process   |
+------------------+         | - Rule 2: Semantic Boundaries |         +-----------------------+
                             | - Rule 3: RFC Exceptions      |
                             +-------------------------------+
```

### Multi-Tiered Inspection Pipeline:
1. **Tier 1 (Role Authorization):** Read operations (`FC 01, 02, 03, 04`) are forwarded without latency. Write commands (`FC 05, 06, 15, 16`) from unauthorized IPs are dropped and answered with **Modbus Exception 0x01 (Illegal Function)**.
2. **Tier 2 (Semantic Boundary Inspection):** Even when a write originates from an authorized Engineering Workstation, the proxy unpacks the register value. If a High Threshold write exceeds safe operating parameters (`value > 900`), the command is rejected with **Modbus Exception 0x03 (Illegal Data Value)** to prevent loss of containment.
3. **Automated Verification:** Run [test_dpi_firewall.py](file:///Users/mo/Articles/PlcSentinel/test_dpi_firewall.py) to simulate attacks against the proxy and verify that OpenPLC's memory remains safe.

