#!/usr/bin/env python3
"""
PlcSentinel - Day 2: Physical Process Simulator (Tank Physics)
Simulates continuous physical dynamics of the water tank:
- When Pump (%QX0.0 / Coil 0) is ON: Inflow increases water level.
- When Drain Valve (%QX0.1 / Coil 1) is OPEN: Outflow rapidly drains tank.
- Interacts with OpenPLC Holding Register 2 (%QW2) to reflect dynamic process level.
"""

import time
import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PHYSICS] %(message)s")
logger = logging.getLogger("ProcessPhysics")

class TankPhysicsSimulator:
    def __init__(self, host="127.0.0.1", port=502):
        self.host = host
        self.port = port
        self.water_level = 150  # Start at 15.0%
        self.inflow_rate = 25   # +2.5% per step when pump is on
        self.drain_rate = 60    # -6.0% per step when drain is open
        self.leak_rate = 2      # -0.2% natural consumption
        self.client = ModbusTcpClient(host=self.host, port=self.port)

    def run_simulation(self, iterations=15, step_interval=1.0):
        if not self.client.connect():
            logger.error("Could not connect to OpenPLC runtime.")
            return

        logger.info(f"Connected to OpenPLC. Starting physical simulation loop ({iterations} cycles)...")
        try:
            for cycle in range(1, iterations + 1):
                # 1. Read Actuator States from OpenPLC
                coils = self.client.read_coils(address=0, count=4, device_id=1).bits[:4]
                pump_on = coils[0]
                drain_open = coils[1]
                alarm_active = coils[2]

                # 2. Compute Physical Water Level Dynamics
                delta = -self.leak_rate
                if pump_on:
                    delta += self.inflow_rate
                if drain_open:
                    delta -= self.drain_rate

                self.water_level = max(0, min(1000, self.water_level + delta))

                # 3. Write Simulated Level to OpenPLC Holding Register 2
                self.client.write_register(address=2, value=int(self.water_level), device_id=1)

                logger.info(
                    f"Cycle {cycle:02d} | Level: {self.water_level:4d}/1000 ({self.water_level/10.0:5.1f}%) | "
                    f"Pump: {'ON ' if pump_on else 'OFF'} | Drain: {'OPEN ' if drain_open else 'SHUT'} | "
                    f"Alarm: {'ALERT' if alarm_active else 'OK   '}"
                )
                time.sleep(step_interval)

        finally:
            self.client.close()
            logger.info("Simulation finished. Connection closed.")

if __name__ == "__main__":
    sim = TankPhysicsSimulator()
    sim.run_simulation(iterations=10, step_interval=0.5)
