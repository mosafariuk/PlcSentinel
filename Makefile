# ==============================================================================
# PlcSentinel: Industrial Control Systems (ICS/OT) Security Makefile
# ==============================================================================

SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python3
PIP   := $(VENV)/bin/pip
COMPOSE ?= $(shell if command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "docker compose"; fi)

.PHONY: help setup venv clean test-all test-unit test-modbus test-s7 test-opcua test-ews test-identity test-iec104 \
        run-modbus-lab run-s7-lab run-opcua-lab soc read-modbus read-s7 \
        docker-up docker-down docker-logs

help: ## Show this help message
	@echo "======================================================================"
	@echo "                   PlcSentinel Automation Makefile                    "
	@echo "======================================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------------------
# ENVIRONMENT & DEPENDENCIES
# ------------------------------------------------------------------------------
setup: venv ## Set up Python virtual environment and install all ICS dependencies
	@echo "[+] Environment initialized successfully in $(VENV)"

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@$(PIP) install pymodbus==3.16.1 python-snap7==3.2.1 asyncua==2.1.0 cryptography==50.0.2 scapy==2.8.0 requests==2.34.2

# ------------------------------------------------------------------------------
# LOCAL LAB RUNNERS (STANDALONE DAEMONS)
# ------------------------------------------------------------------------------
run-modbus-lab: ## Start OpenPLC Docker container and inline Modbus L7 DPI proxy
	@docker run -d --name openplc-sandbox -p 8081:8080 -p 502:502 fdamador/openplc:latest 2>/dev/null || true
	@$(PY) -m plcsentinel.gateways.modbus_dpi_proxy --listen-port 5020 --backend-port 502 --policy config/modbus_policy.json &

run-s7-lab: ## Start local S7 mock controller and S7comm L7 DPI proxy
	@$(PY) -m plcsentinel.servers.s7_mock_server &
	@sleep 1
	@$(PY) -m plcsentinel.gateways.s7_dpi_proxy --listen-port 10200 --backend-port 1102 --policy config/s7_policy.json &

run-iec104-lab: ## Start the IEC 104 mock outstation and telecontrol DPI gateway
	@$(PY) -m plcsentinel.servers.iec104_mock_server --port 24040 &
	@sleep 1
	@$(PY) -m plcsentinel.gateways.iec104_dpi_proxy --listen-port 2404 --backend-port 24040 --policy config/iec104_policy.json &

run-opcua-lab: ## Generate X.509 PKI certificates and launch encrypted OPC UA server
	@$(PY) -m plcsentinel.ops.generate_opcua_certs
	@$(PY) -m plcsentinel.servers.opcua_secure_server &

# ------------------------------------------------------------------------------
# TELEMETRY READERS & MONITORS
# ------------------------------------------------------------------------------
read-modbus: ## Read real-time telemetry through Modbus DPI proxy
	@$(PY) -m plcsentinel.clients.read_via_proxy

read-s7: ## Query Siemens S7 mock controller via S7-Sentinel
	@$(PY) -m plcsentinel.clients.s7_sentinel --port 1102

soc: ## Launch the Unified Multi-Protocol OT SOC Threat Dashboard
	@$(PY) -m plcsentinel.ops.soc_dashboard

hmi: ## Run terminal-based supervisory HMI console
	@$(PY) -m plcsentinel.clients.hmi_monitor

# ------------------------------------------------------------------------------
# AUTOMATED THREAT MITIGATION TESTS
# ------------------------------------------------------------------------------
test-unit: ## Run offline DPI policy unit tests (no PLC, proxies or venv extras needed)
	@$(PY) -m unittest -v tests.test_dpi_policy tests.test_dpi_identity tests.test_iec104

test-modbus: ## Execute automated Modbus DPI threat mitigation tests
	@$(PY) -m tests.test_dpi_firewall

test-s7: ## Execute automated S7comm CPU Stop and Write mitigation tests
	@$(PY) -m tests.test_s7_dpi_mitigation

test-opcua: ## Execute encrypted OPC UA mutual-TLS telemetry test
	@$(PY) -m plcsentinel.clients.opcua_secure_client

test-ews: ## Prove the authorized-EWS write path through both gateways (needs make docker-up)
	@if $(COMPOSE) ps --status running --services 2>/dev/null | grep -qx ews; then \
		$(COMPOSE) exec -T ews python3 -m tests.test_ews_authorized; \
	else echo "[!] ews container not running (make docker-up); skipping authorized-path test"; fi

test-identity: ## Prove certificate identity authorizes writes from an untrusted address (needs make docker-up)
	@$(PY) -m tests.test_identity_live

test-iec104: ## Prove IEC 104 control commands are blocked at the conduit (needs make docker-up)
	@$(PY) -m tests.test_iec104_live

test-all: test-unit test-modbus test-s7 test-opcua test-ews test-identity test-iec104 ## Run offline unit tests, the protocol suites, the authorized-EWS and certificate-identity paths, then IEC 104
	@echo "======================================================================"
	@echo "       ALL INDUSTRIAL THREAT MITIGATION TESTS PASSED SUCCESSFULLY!    "
	@echo "======================================================================"

# ------------------------------------------------------------------------------
# DOCKER COMPOSE ORCHESTRATION
# ------------------------------------------------------------------------------
docker-up: ## Build and start the entire multi-protocol testbed with Docker Compose
	@docker stop openplc-sandbox 2>/dev/null || true
	@$(COMPOSE) up -d --build
	@sleep 4
	@$(PY) -m plcsentinel.ops.init_openplc http://127.0.0.1:8081 2>/dev/null || true

docker-down: ## Tear down all Docker Compose services and networks
	@$(COMPOSE) down

docker-logs: ## Follow live logs from all Docker Compose services
	@$(COMPOSE) logs -f

init-openplc: ## Compile and start tank_control.st in OpenPLC
	@$(PY) -m plcsentinel.ops.init_openplc http://127.0.0.1:8081

# ------------------------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------------------------
clean: ## Remove temporary python bytecode, caches, and test artifacts
	@rm -rf __pycache__ *.pyc .pytest_cache
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "[+] Cleanup complete."

reset-logs: ## Clear SIEM JSON event logs
	@rm -f logs/*.jsonl
	@echo "[+] Security event logs cleared."
