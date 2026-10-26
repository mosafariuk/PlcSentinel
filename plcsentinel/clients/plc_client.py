#!/usr/bin/env python3
"""
PlcSentinel - Safe Local Modbus TCP Master/Client for OpenPLC
Author: Senior ICS/OT Cybersecurity Specialist
Purpose: Verification and benign interaction with OpenPLC runtime in an isolated lab.
"""

import sys
import time
import logging

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    try:
        from pymodbus.client.sync import ModbusTcpClient
    except ImportError:
        print("[!] pymodbus is not installed. Install via: pip install pymodbus")
        sys.exit(1)

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("PlcSentinel")

class OpenPLCTester:
    def __init__(self, host: str = "127.0.0.1", port: int = 502, unit_id: int = 1):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.client = ModbusTcpClient(host=self.host, port=self.port)

    def connect(self) -> bool:
        logger.info(f"Connecting to OpenPLC at {self.host}:{self.port}...")
        if self.client.connect():
            logger.info("Successfully established Modbus TCP connection.")
            return True
        logger.error(f"Failed to connect to {self.host}:{self.port}. Is OpenPLC running?")
        return False

    def close(self):
        self.client.close()
        logger.info("Closed Modbus TCP connection.")

    def read_system_telemetry(self):
        """
        Reads OpenPLC digital outputs (%QX0.0..%QX0.3) via FC 01 (Read Coils)
        and Holding Registers (%QW0..%QW1) via FC 03 (Read Holding Registers).
        """
        logger.info("--- Polling OpenPLC Telemetry ---")
        
        # 1. Read Coils (Discrete Outputs: Pump, Drain, Alarm, Override)
        # In OpenPLC: %QX0.0 maps to Coil Address 0
        coils_res = self.client.read_coils(address=0, count=4, device_id=self.unit_id)
        if hasattr(coils_res, 'isError') and coils_res.isError():
            logger.warning(f"Error reading coils: {coils_res}")
        else:
            coils = coils_res.bits[:4]
            logger.info(f"Actuator States [Coils 0-3]:")
            logger.info(f"  Pump Motor  (%QX0.0 / Coil 0): {'ON' if coils[0] else 'OFF'}")
            logger.info(f"  Drain Valve (%QX0.1 / Coil 1): {'OPEN' if coils[1] else 'CLOSED'}")
            logger.info(f"  Alarm Light (%QX0.2 / Coil 2): {'ACTIVE' if coils[2] else 'NORMAL'}")
            logger.info(f"  Manual Mode (%QX0.3 / Coil 3): {'MANUAL' if coils[3] else 'AUTO'}")

        # 2. Read Holding Registers (Thresholds: %QW0, %QW1)
        # In OpenPLC: %QW0 maps to Holding Register Address 0
        regs_res = self.client.read_holding_registers(address=0, count=2, device_id=self.unit_id)
        if hasattr(regs_res, 'isError') and regs_res.isError():
            logger.warning(f"Error reading holding registers: {regs_res}")
        else:
            regs = regs_res.registers
            logger.info(f"Configuration Setpoints [Holding Regs 0-1]:")
            logger.info(f"  High Threshold (%QW0 / Reg 0): {regs[0]} ({regs[0]/10.0:.1f}%)")
            logger.info(f"  Low Threshold  (%QW1 / Reg 1): {regs[1]} ({regs[1]/10.0:.1f}%)")

    def simulate_telemetry_stream(self, duration_sec: int = 10, poll_interval_sec: float = 2.0):
        """Monitors the runtime state over a fixed duration."""
        logger.info(f"Starting telemetry monitoring for {duration_sec}s...")
        end_time = time.time() + duration_sec
        try:
            while time.time() < end_time:
                self.read_system_telemetry()
                time.sleep(poll_interval_sec)
        except KeyboardInterrupt:
            logger.info("Monitoring terminated by user.")

    def set_threshold_safely(self, high_val: int = 800, low_val: int = 250):
        """
        Safely writes new operational limits using FC 06 (Write Single Register)
        or FC 16 (Write Multiple Registers) within safe boundaries.
        """
        # Strict sanity checks for boundary protection
        if not (0 <= low_val < high_val <= 1000):
            logger.error("Boundary Violation: low_val must be strictly less than high_val and within 0..1000.")
            return False

        logger.info(f"Writing safe thresholds: High={high_val}, Low={low_val}...")
        # Write High Threshold to %QW0 (address 0)
        res_high = self.client.write_register(address=0, value=high_val, device_id=self.unit_id)
        # Write Low Threshold to %QW1 (address 1)
        res_low = self.client.write_register(address=1, value=low_val, device_id=self.unit_id)
        
        logger.info(f"Write High Response: {res_high}")
        logger.info(f"Write Low Response: {res_low}")
        return True

if __name__ == "__main__":
    tester = OpenPLCTester(host="127.0.0.1", port=502)
    if tester.connect():
        tester.read_system_telemetry()
        # Example safe setpoint update
        # tester.set_threshold_safely(high_val=850, low_val=220)
        tester.close()
