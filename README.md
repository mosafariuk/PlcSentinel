# PlcSentinel: Industrial Control Systems (ICS/OT) Security Testbed

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: IEC 62443](https://img.shields.io/badge/Standard-IEC%2062443-blue.svg)](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
[![Protocols: Modbus | S7comm | OPC UA](https://img.shields.io/badge/Protocols-Modbus%20%7C%20S7comm%20%7C%20OPC%20UA-brightgreen.svg)](#supported-protocols)

**PlcSentinel** is a production-grade, local, and reproducible Industrial Control Systems (ICS) security laboratory and active defense toolkit. It models realistic industrial processes, dissects unauthenticated legacy protocols, simulates weaponized threat techniques (mapped to **MITRE ATT&CK for ICS**), and deploys inline **Layer-7 Deep Packet Inspection (DPI)** mitigation proxies.

---

## Architecture Overview

```
+---------------------------------------------------------------------------------+
| LEVEL 2: SUPERVISORY & CONTROL ZONE                                             |
| - Operator HMI Display (Read-Only Telemetry Polling)                            |
| - Engineering Workstation (Authorized Logic Modifications & Validated Writes)   |
+---------------------------------------------------------------------------------+
                                       ||
                 [Conduit C-1: Layer-7 Active DPI Gateways]
                 - Modbus TCP L7 DPI Proxy (Port 5020 -> 502)
                 - Siemens S7comm L7 DPI Proxy (Port 10200 -> 1102 / 102)
                                       ||
+---------------------------------------------------------------------------------+
| LEVEL 1: BASIC PROCESS CONTROL ZONE                                             |
| - OpenPLC v3 Runtime (Deterministic 50ms Scan Cycle)                            |
| - Siemens Simatic S7 Mock Controller (S7comm over ISO-on-TCP RFC 1006)          |
| - Encrypted OPC UA Server (IEC 62541 / Basic256Sha256 SignAndEncrypt)           |
+---------------------------------------------------------------------------------+
                                       ||
                        [Hardwired Process Conduits]
                                       ||
+---------------------------------------------------------------------------------+
| LEVEL 0: PHYSICAL PROCESS (Hydraulic Tank Simulation)                          |
| - Inflow Pump Contactor (%QX0.0), Emergency Drain Valve (%QX0.1)                |
| - Float Switches (%IX0.0, %IX0.1), Hardwired Emergency Stop Relay (%QX0.4)      |
+---------------------------------------------------------------------------------+
```

---

## Key Features

1. **Multi-Protocol Coverage:**
   * **Modbus TCP:** Deterministic IEC 61131-3 Structured Text logic ([tank_control.st](tank_control.st)), packet forensics ([inspect_pcap.py](inspect_pcap.py)), and attack suite ([ot_attack_suite.py](ot_attack_suite.py)).
   * **Siemens S7comm (Port 102):** S7 assessment client ([s7_sentinel.py](s7_sentinel.py)) with read-back verification and an inline S7 DPI gateway ([s7_dpi_proxy.py](s7_dpi_proxy.py)) blocking CPU Stop (`0x29`) and restricting all writes (`0x05`), logic download/upload and run-mode changes to the authorized EWS.
   * **OPC UA (IEC 62541):** Mutual X.509 PKI certificate generation ([generate_opcua_certs.py](generate_opcua_certs.py)), secure server ([opcua_secure_server.py](opcua_secure_server.py)), and encrypted client ([opcua_secure_client.py](opcua_secure_client.py)).
2. **Inline Layer-7 Active Mitigation:**
   * Only read operations are open to every host. Writes, masked and combined writes, diagnostics, vendor codes, logic transfers and S7 UserData requests (other than status reads) require the authorized engineering-workstation identity.
   * Synthesizes RFC-compliant Modbus Exceptions (`0x01` Illegal Function, `0x03` Illegal Data Value).
   * Enforces semantic process safety boundaries (e.g. overfill protection thresholds).
   * Policy lives in `modbus_policy.json` / `s7_policy.json` (authorized stations, open function codes, protected registers and their limits), validated at startup; CLI flags override it.
   * Per-source caps on concurrent sessions and requests per second (policy keys `max_sessions_per_source`, `max_requests_per_second`) stop one host exhausting the controller's connection table through the gateway; they apply in both modes and log MITRE T0814 events.
   * For protocols without a dedicated gateway yet (EtherNet/IP, Unitronics PCOM, vendor engineering protocols), [tls_conduit.py](tls_conduit.py) is an identity-gated conduit: mutual TLS, certificate allow list, per-source caps and ECS logging, then a byte-for-byte relay. Authentication without inspection, which still removes the controller's exposure.
   * `--monitor` runs either gateway inline in detect-only mode: violations are logged as `detected` and forwarded, so a site can observe before enforcing.
   * Authorization is by **principal**: a source IP on the plain listeners (a compensating control for legacy stations) or, on the mutual-TLS listeners (Modbus/TCP Security on 802, S7 on 10202), the **Common Name of a client certificate** issued by the lab CA. Engineering tools that cannot speak TLS reach the S7 gateway through [ews_tls_tunnel.py](ews_tls_tunnel.py). The controller side stays plain: the conduit terminates the identity.
3. **Unified OT SOC Threat Dashboard:**
   * Console-based SIEM dashboard ([soc_dashboard.py](soc_dashboard.py)) streaming structured **Elastic Common Schema (ECS)** logs enriched with MITRE ATT&CK for ICS tags (`T0855`, `T0836`, `T0805`).
   * `--siem-udp HOST:PORT` on either gateway also forwards every event as a JSON datagram to an Elastic, Logstash or Wazuh collector, so no shared log volume is needed.
4. **Complete Technical Documentation:**
   * [ARTICLE_PlcSentinel_ICS_Security.md](ARTICLE_PlcSentinel_ICS_Security.md): Full publication-grade whitepaper.
   * [PlcSentinel_Lab_Guide.md](PlcSentinel_Lab_Guide.md): 7-Day structured hands-on curriculum.
   * [iec62443_hardening_report.md](iec62443_hardening_report.md): Purdue Model and IEC 62443 compliance roadmap.

---

## Quickstart

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/your-username/PlcSentinel.git
cd PlcSentinel

# Initialize virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install pymodbus scapy asyncua cryptography requests python-snap7
```

### 2. Launch Modbus L7 DPI Gateway & OpenPLC
```bash
# Start Dockerized OpenPLC Runtime
docker run -d --name openplc-sandbox -p 8081:8080 -p 502:502 fdamador/openplc:latest

# Start Modbus L7 DPI Proxy
python3 modbus_dpi_proxy.py --listen-port 5020 --backend-port 502 --policy modbus_policy.json &

# Read live telemetry safely through the proxy
python3 read_via_proxy.py
```

### 3. Launch Siemens S7 Toolkit
```bash
# Start local S7 mock controller
python3 s7_mock_server.py &

# Start S7comm Layer-7 DPI Proxy
python3 s7_dpi_proxy.py --listen-port 10200 --backend-port 1102 --policy s7_policy.json &

# Run automated S7 active mitigation test
python3 test_s7_dpi_mitigation.py
```

### 4. Launch Encrypted OPC UA Communication
```bash
# Generate X.509 certificates
python3 generate_opcua_certs.py

# Start secure OPC UA server
python3 opcua_secure_server.py &

# Query over encrypted channel (Basic256Sha256)
python3 opcua_secure_client.py
```

### 5. Monitor Live OT Threat Telemetry
```bash
python3 soc_dashboard.py
```

---

## Repository Structure

```
PlcSentinel/
├── ARTICLE_PlcSentinel_ICS_Security.md  # Publication-grade whitepaper
├── PlcSentinel_Lab_Guide.md             # 7-day lab curriculum
├── iec62443_hardening_report.md         # IEC 62443 compliance report
├── wireshark_filters.txt                # Curated Wireshark filters & color rules
├── tank_control.st                      # IEC 61131-3 Structured Text logic
├── dpi_limits.py                        # Per-source session and request-rate caps shared by both gateways
├── modbus_dpi_proxy.py                  # Inline Modbus L7 DPI Gateway with ECS logging
├── modbus_policy.json                   # Modbus gateway policy: authorized EWS, open FCs, protected registers
├── read_via_proxy.py                    # Telemetry reader via Modbus DPI proxy
├── test_dpi_firewall.py                 # Automated Modbus mitigation test suite
├── test_dpi_policy.py                   # Offline unit tests for both DPI policy engines (no services needed)
├── test_dpi_identity.py                 # Mutual-TLS identity tests (mints a throwaway PKI per run)
├── test_ews_authorized.py               # Authorized-EWS write path test, run inside the ews container
├── test_identity_live.py                # Certificate-identity path test from the host (TLS listeners)
├── ot_attack_suite.py                   # MITRE ATT&CK for ICS exploit simulation
├── hmi_monitor.py                       # Terminal-based supervisory HMI console
├── inspect_pcap.py                      # Forensic Modbus TCP frame dissector
├── modbus_lab_traffic.pcap              # Reference packet capture
├── s7_sentinel.py                       # Siemens S7comm assessment & telemetry client
├── s7_mock_server.py                    # Local Siemens S7-300/1200 mock controller
├── s7_dpi_proxy.py                      # Inline S7comm L7 DPI Gateway (CPU Stop interceptor)
├── s7_policy.json                       # S7 gateway policy: authorized EWS, open jobs and UserData
├── test_s7_dpi_mitigation.py            # S7 DPI mitigation test suite
├── generate_opcua_certs.py              # X.509 RSA PKI certificate generator
├── generate_gateway_certs.py            # Lab CA, gateway and EWS certificates for the mutual-TLS conduits
├── dpi_tls.py                           # Mutual-TLS helpers shared by the gateways and the EWS tunnel
├── ews_tls_tunnel.py                    # EWS-side tunnel: local plain port -> mutual TLS -> gateway
├── tls_conduit.py                       # Identity-gated relay for protocols without a dedicated gateway
├── opcua_secure_server.py               # IEC 62541 Secure OPC UA server
├── opcua_secure_client.py               # Mutual X.509 authenticated OPC UA client
├── opcua_vs_modbus.py                   # Protocol security comparison matrix
├── soc_dashboard.py                     # Unified Multi-Protocol OT SOC Dashboard
├── certs/                               # X.509 certificates and RSA keys
├── logs/                                # Structured ECS JSON SIEM event logs
└── rules/
    └── suricata_modbus.rules            # Suricata / Snort OT detection signatures
```

---

## License

This project is released under the [MIT License](LICENSE). Designed for educational, research, and authorized assessment purposes only.
