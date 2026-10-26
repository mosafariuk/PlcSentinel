# IEC 62443 Security Architecture & Hardening Blueprint
**Target System:** OpenPLC Water Level Control Loop (Level 1 Process Control)  
**Standard Reference:** IEC 62443-3-2 (Zones & Conduits), IEC 62443-3-3 (System Requirements), IEC 62443-4-2 (Component Requirements)

---

## 1. Purdue Model Zone & Conduit Architecture

```
+---------------------------------------------------------------------------------+
| ENTERPRISE ZONE (Levels 4 & 5)                                                  |
| Enterprise Resource Planning (ERP), Corporate IT, Cloud Analytics              |
+---------------------------------------------------------------------------------+
                                      ||
                        [Conduit C-3.5: Enterprise DMZ]
                                      ||
+---------------------------------------------------------------------------------+
| INDUSTRIAL DMZ (Level 3.5)                                                      |
| Replicated Historian, Patch Management, Jump Host, Remote Access VPN            |
+---------------------------------------------------------------------------------+
                                      ||
                        [Conduit C-3: OT Boundary Firewall]
                                      ||
+---------------------------------------------------------------------------------+
| OPERATIONS & SUPERVISORY ZONE (Level 3)                                         |
| Plant SCADA Server, Central Engineering Server, Primary Historian               |
+---------------------------------------------------------------------------------+
                                      ||
                        [Conduit C-2: Internal OT Firewall]
                                      ||
+---------------------------------------------------------------------------------+
| CONTROL ZONE (Level 2)                                                          |
| - Local Operator HMI (192.168.1.10) [Read-Only Modbus Queries]                  |
| - Authorized Engineering Workstation (EWS) (192.168.1.50) [Modbus Configuration]|
+---------------------------------------------------------------------------------+
                                      ||
                        [Conduit C-1: Micro-Segmentation / Modbus DPI Firewall]
                                      ||
+---------------------------------------------------------------------------------+
| BASIC CONTROL ZONE (Level 1)                                                    |
| - OpenPLC Controller (192.168.1.100 : Port 502/TCP)                             |
| - Safety Instrumented System (SIS) [Independent Hardwired Safety Loop]          |
+---------------------------------------------------------------------------------+
                                      ||
                        [Hardwired Process Conduits]
                                      ||
+---------------------------------------------------------------------------------+
| PROCESS ZONE (Level 0)                                                          |
| - Sensors: Float Switches (%IX0.0, %IX0.1), Analog Level Probe (%QW2)           |
| - Actuators: Inflow Pump Contactor (%QX0.0), Emergency Drain Valve (%QX0.1)     |
+---------------------------------------------------------------------------------+
```

---

## 2. Conduit Policy Enforcement (Modbus DPI Rules)

Industrial firewalls (or software appliances such as Linux `nftables` or Suricata inline IPS) defending **Conduit C-1** must enforce Layer 7 protocol filtering:

```
+------------------+------------------+---------------+--------------------------------------+
| Source Device    | Destination      | Modbus FC     | Policy Action / Filter               |
+------------------+------------------+---------------+--------------------------------------+
| Operator HMI     | OpenPLC:502      | FC 01, 02,    | ALLOW (Read-Only Telemetry)          |
| (192.168.1.10)   |                  | 03, 04        |                                      |
+------------------+------------------+---------------+--------------------------------------+
| Operator HMI     | OpenPLC:502      | FC 05, 06,    | DROP & ALERT (Unauthorized Write)    |
| (192.168.1.10)   |                  | 15, 16        |                                      |
+------------------+------------------+---------------+--------------------------------------+
| Engineering Stn  | OpenPLC:502      | Any FC        | ALLOW (Subject to Maintenance Window)|
| (192.168.1.50)   |                  |               |                                      |
+------------------+------------------+---------------+--------------------------------------+
| Any Other Host   | OpenPLC:502      | Any FC        | REJECT & LOG (Intrusion Attempt)     |
+------------------+------------------+---------------+--------------------------------------+
```

### Production Linux `nftables` / `iptables` Example:
```bash
# Allow Modbus TCP port 502 only from authorized control network
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 502 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 502 -j DROP

# Isolate OpenPLC Web GUI (port 8080/8081) to Engineering Subnet ONLY
iptables -A INPUT -p tcp -s 192.168.1.50 --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

---

## 3. IEC 62443-3-3 Foundational Requirements (FR) Gap Audit

| FR Code | Requirement Category | Current Lab State | Target Hardening Recommendation |
| :--- | :--- | :--- | :--- |
| **FR 1** | **Identification & Authentication (IAC)** | Default admin/openplc credentials initially present. | Enforce strong passwords; implement role-based access control (RBAC); migrate from Modbus TCP to Modbus Security (TLS encapsulation / IEC 62443-4-2). |
| **FR 2** | **Use Control (UC)** | Any connected host can issue write requests. | Enforce DPI firewall rules restricting write function codes (FC 05, 06, 16) to authorized EWS MAC/IP pairs. |
| **FR 3** | **System Integrity (SI)** | Control logic and register memory vulnerable to in-flight tampering. | Sign compiled binary artifacts; enforce physical key-switch on physical PLCs (RUN vs PROG mode). |
| **FR 4** | **Data Confidentiality (DC)** | Modbus TCP transmits process measurements in plaintext. | Encapsulate Modbus inside IPsec/WireGuard tunnels across intermediate switches or use Modbus/TLS (Port 802). |
| **FR 5** | **Restricted Data Flow (RDF)** | Flat network topology allows any client to contact port 502. | Implement Purdue Model Zones & Conduits via managed switches (802.1Q VLANs) and stateful OT firewalls. |
| **FR 6** | **Timely Response to Events (TRE)** | No native audit log on basic Modbus communication. | Deploy passive network taps streaming traffic to Suricata/Zeek and forward alerts to industrial SIEM (e.g. Wazuh). |
| **FR 7** | **Resource Availability (RA)** | Controller vulnerable to connection exhaustion and packet floods. | Implement TCP connection rate-limiting and SYN-flood protection on upstream switches. |

---

## 4. Hardware Safety Decoupling (The Golden Rule of ICS Defense)

Software controls, network segmentation, and encryption **must never be the sole line of defense against loss of life or containment breaches**.
* **Hardwired Interlocks (Level 0):** The High-Level Float switch (`%IX0.1`) and Emergency Stop (`%QX0.4`) must be physically wired in series with the inflow pump contactor coil power supply.
* If an attacker compromises the PLC firmware or executes setpoint poisoning (writing `9999`), the physical circuit breaks as soon as water trips the mechanical float, cutting power to the pump regardless of corrupted software memory.
