# PlcSentinel: Industrial Control Systems (ICS/OT) Security Testbed

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: IEC 62443](https://img.shields.io/badge/Standard-IEC%2062443-blue.svg)](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
[![Protocols: Modbus | S7comm | OPC UA | IEC 104](https://img.shields.io/badge/Protocols-Modbus%20%7C%20S7comm%20%7C%20OPC%20UA%20%7C%20IEC%20104-brightgreen.svg)](#supported-protocols)

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
   * **Modbus TCP:** Deterministic IEC 61131-3 Structured Text logic ([tank_control.st](plc/tank_control.st)), packet forensics ([inspect_pcap.py](plcsentinel/redteam/inspect_pcap.py)), and attack suite ([ot_attack_suite.py](plcsentinel/redteam/ot_attack_suite.py)).
   * **Siemens S7comm (Port 102):** S7 assessment client ([s7_sentinel.py](plcsentinel/clients/s7_sentinel.py)) with read-back verification and an inline S7 DPI gateway ([s7_dpi_proxy.py](plcsentinel/gateways/s7_dpi_proxy.py)) blocking CPU Stop (`0x29`) and restricting all writes (`0x05`), logic download/upload and run-mode changes to the authorized EWS.
   * **OPC UA (IEC 62541):** Mutual X.509 PKI certificate generation ([generate_opcua_certs.py](plcsentinel/ops/generate_opcua_certs.py)), secure server ([opcua_secure_server.py](plcsentinel/servers/opcua_secure_server.py)), and encrypted client ([opcua_secure_client.py](plcsentinel/clients/opcua_secure_client.py)).
2. **Inline Layer-7 Active Mitigation:**
   * Only read operations are open to every host. Writes, masked and combined writes, diagnostics, vendor codes, logic transfers and S7 UserData requests (other than status reads) require the authorized engineering-workstation identity.
   * Synthesizes RFC-compliant Modbus Exceptions (`0x01` Illegal Function, `0x03` Illegal Data Value).
   * Enforces semantic process safety boundaries (e.g. overfill protection thresholds).
   * Policy lives in `modbus_policy.json` / `s7_policy.json` (authorized stations, open function codes, protected registers and their limits), validated at startup; CLI flags override it.
   * Per-source caps on concurrent sessions and requests per second (policy keys `max_sessions_per_source`, `max_requests_per_second`) stop one host exhausting the controller's connection table through the gateway; they apply in both modes and log MITRE T0814 events.
   * **IEC 60870-5-104 (Port 2404):** inline telecontrol gateway ([iec104_dpi_proxy.py](plcsentinel/gateways/iec104_dpi_proxy.py)) that restricts control commands (types 45-51, 58-64, 100-107) to the authorized EWS, refuses Reset Process (type 105) for everyone, and bounds set-point commands by object address. This is the protocol behind the 2016 Industroyer grid attack.
   * For protocols without a dedicated gateway yet (EtherNet/IP, Unitronics PCOM, vendor engineering protocols), [tls_conduit.py](plcsentinel/gateways/tls_conduit.py) is an identity-gated conduit: mutual TLS, certificate allow list, per-source caps and ECS logging, then a byte-for-byte relay. Authentication without inspection, which still removes the controller's exposure.
   * `--monitor` runs either gateway inline in detect-only mode: violations are logged as `detected` and forwarded, so a site can observe before enforcing.
   * Authorization is by **principal**: a source IP on the plain listeners (a compensating control for legacy stations) or, on the mutual-TLS listeners (Modbus/TCP Security on 802, S7 on 10202), the **Common Name of a client certificate** issued by the lab CA. Engineering tools that cannot speak TLS reach the S7 gateway through [ews_tls_tunnel.py](plcsentinel/clients/ews_tls_tunnel.py). The controller side stays plain: the conduit terminates the identity.
3. **Unified OT SOC Threat Dashboard:**
   * Console-based SIEM dashboard ([soc_dashboard.py](plcsentinel/ops/soc_dashboard.py)) streaming structured **Elastic Common Schema (ECS)** logs enriched with MITRE ATT&CK for ICS tags (`T0855`, `T0836`, `T0805`).
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
python3 -m plcsentinel.gateways.modbus_dpi_proxy --listen-port 5020 --backend-port 502 --policy config/modbus_policy.json &

# Read live telemetry safely through the proxy
python3 -m plcsentinel.clients.read_via_proxy
```

### 3. Launch Siemens S7 Toolkit
```bash
# Start local S7 mock controller
python3 -m plcsentinel.servers.s7_mock_server &

# Start S7comm Layer-7 DPI Proxy
python3 -m plcsentinel.gateways.s7_dpi_proxy --listen-port 10200 --backend-port 1102 --policy config/s7_policy.json &

# Run automated S7 active mitigation test
python3 -m tests.test_s7_dpi_mitigation
```

### 4. Launch Encrypted OPC UA Communication
```bash
# Generate X.509 certificates
python3 -m plcsentinel.ops.generate_opcua_certs

# Start secure OPC UA server
python3 -m plcsentinel.servers.opcua_secure_server &

# Query over encrypted channel (Basic256Sha256)
python3 -m plcsentinel.clients.opcua_secure_client
```

### 5. Monitor Live OT Threat Telemetry
```bash
python3 -m plcsentinel.ops.soc_dashboard
```

---

## Running modules directly

Every tool runs as a package module from the repository root, e.g. `python3 -m plcsentinel.gateways.modbus_dpi_proxy --help`. The `make` targets and `docker compose` services wrap these, so day-to-day you use `make run-modbus-lab`, `make test-all`, `make docker-up` as before.

## Repository Structure

```
PlcSentinel/
├── plcsentinel/                 # Python package (run modules with `python -m plcsentinel...`)
│   ├── core/                    # shared transport, caps and TLS helpers
│   │   ├── dpi_stream.py        #   asyncio listeners, caps, monitor mode, ECS logging, policy loader
│   │   ├── dpi_limits.py        #   per-source session and request-rate caps
│   │   └── dpi_tls.py           #   mutual-TLS contexts and certificate-principal extraction
│   ├── gateways/                # inline Layer-7 DPI gateways
│   │   ├── modbus_dpi_proxy.py  #   Modbus TCP gateway
│   │   ├── s7_dpi_proxy.py      #   Siemens S7comm gateway (CPU-Stop interceptor, change windows)
│   │   ├── iec104_dpi_proxy.py  #   IEC 60870-5-104 telecontrol gateway
│   │   └── tls_conduit.py       #   identity-gated relay for protocols without a parser
│   ├── clients/                 # HMI, telemetry and the EWS-side TLS tunnel
│   │   ├── hmi_monitor.py  plc_client.py  read_via_proxy.py
│   │   ├── s7_sentinel.py  opcua_secure_client.py  ews_tls_tunnel.py
│   ├── servers/                 # mock controllers and the OPC UA server
│   │   ├── s7_mock_server.py  iec104_mock_server.py  opcua_secure_server.py
│   ├── redteam/                 # attack suite and PCAP forensics
│   │   ├── ot_attack_suite.py  generate_lab_pcap_and_attacks.py
│   │   ├── detect_anomalies.py  inspect_pcap.py  opcua_vs_modbus.py
│   ├── sim/
│   │   └── tank_process_simulator.py
│   └── ops/                     # dashboard, provisioning and PKI generation
│       ├── soc_dashboard.py  init_openplc.py
│       └── generate_opcua_certs.py  generate_gateway_certs.py
├── tests/                       # offline unit suites + live end-to-end tests
├── config/                      # modbus_policy.json  s7_policy.json  iec104_policy.json
├── plc/                         # tank_control.st (IEC 61131-3 logic)
├── rules/                       # suricata_modbus.rules  wireshark_filters.txt
├── docs/                        # whitepaper, lab guide, hardening report, IR playbook
├── data/                        # modbus_lab_traffic.pcap
├── certs/                       # generated X.509 PKI (git-ignored)
├── logs/                        # structured ECS JSON SIEM event logs
├── Makefile  docker-compose.yml  Dockerfile  requirements.txt
└── README.md  LICENSE
```

---

## License

This project is released under the [MIT License](LICENSE). Designed for educational, research, and authorized assessment purposes only.
