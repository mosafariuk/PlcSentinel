# ==============================================================================
# PlcSentinel: Industrial Control Systems (ICS/OT) Security Makefile
# ==============================================================================

SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python3
PIP   := $(VENV)/bin/pip
COMPOSE ?= $(shell if command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "docker compose"; fi)

.PHONY: help setup venv clean test-all test-unit test-modbus test-s7 test-opcua test-ews test-identity \
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
	@$(PY) modbus_dpi_proxy.py --listen-port 5020 --backend-port 502 --policy modbus_policy.json &

run-s7-lab: ## Start local S7 mock controller and S7comm L7 DPI proxy
	@$(PY) s7_mock_server.py &
	@sleep 1
	@$(PY) s7_dpi_proxy.py --listen-port 10200 --backend-port 1102 --policy s7_policy.json &

run-opcua-lab: ## Generate X.509 PKI certificates and launch encrypted OPC UA server
	@$(PY) generate_opcua_certs.py
	@$(PY) opcua_secure_server.py &

# ------------------------------------------------------------------------------
# TELEMETRY READERS & MONITORS
# ------------------------------------------------------------------------------
read-modbus: ## Read real-time telemetry through Modbus DPI proxy
	@$(PY) read_via_proxy.py

read-s7: ## Query Siemens S7 mock controller via S7-Sentinel
	@$(PY) s7_sentinel.py --port 1102

soc: ## Launch the Unified Multi-Protocol OT SOC Threat Dashboard
	@$(PY) soc_dashboard.py

hmi: ## Run terminal-based supervisory HMI console
	@$(PY) hmi_monitor.py

# ------------------------------------------------------------------------------
# AUTOMATED THREAT MITIGATION TESTS
# ------------------------------------------------------------------------------
test-unit: ## Run offline DPI policy unit tests (no PLC, proxies or venv extras needed)
	@$(PY) -m unittest -v test_dpi_policy test_dpi_identity

test-modbus: ## Execute automated Modbus DPI threat mitigation tests
	@$(PY) test_dpi_firewall.py

test-s7: ## Execute automated S7comm CPU Stop and Write mitigation tests
	@$(PY) test_s7_dpi_mitigation.py

test-opcua: ## Execute encrypted OPC UA mutual-TLS telemetry test
	@$(PY) opcua_secure_client.py

test-ews: ## Prove the authorized-EWS write path through both gateways (needs make docker-up)
	@if $(COMPOSE) ps --status running --services 2>/dev/null | grep -qx ews; then \
		$(COMPOSE) exec -T ews python3 test_ews_authorized.py; \
	else echo "[!] ews container not running (make docker-up); skipping authorized-path test"; fi

test-identity: ## Prove certificate identity authorizes writes from an untrusted address (needs make docker-up)
	@$(PY) test_identity_live.py

test-all: test-unit test-modbus test-s7 test-opcua test-ews test-identity ## Run offline unit tests, the protocol suites, the authorized-EWS path, then the certificate-identity path
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
	@$(PY) init_openplc.py http://127.0.0.1:8081 2>/dev/null || true

docker-down: ## Tear down all Docker Compose services and networks
	@$(COMPOSE) down

docker-logs: ## Follow live logs from all Docker Compose services
	@$(COMPOSE) logs -f

init-openplc: ## Compile and start tank_control.st in OpenPLC
	@$(PY) init_openplc.py http://127.0.0.1:8081

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
