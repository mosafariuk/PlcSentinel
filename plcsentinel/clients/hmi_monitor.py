#!/usr/bin/env python3
"""
PlcSentinel - Day 4: Industrial HMI & Telemetry Monitor (Level 2 Supervisory)
Provides an operator console with real-time ASCII process graphics,
actuator annunciator status, and safe manual setpoint controls.
"""

import os
import sys
import time
from pymodbus.client import ModbusTcpClient

class IndustrialHMI:
    def __init__(self, host="127.0.0.1", port=502):
        self.host = host
        self.port = port
        self.client = ModbusTcpClient(host=self.host, port=self.port)
        self.poll_count = 0
        self.error_count = 0

    def draw_screen(self, coils, holding_regs, level_val):
        pump_on = coils[0]
        drain_open = coils[1]
        alarm_on = coils[2]
        manual_mode = coils[3]

        high_thresh = holding_regs[0]
        low_thresh = holding_regs[1]

        level_pct = level_val / 10.0
        bar_len = 30
        filled = int((level_val / 1000.0) * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        print("\033[H\033[J", end="")  # Clear terminal
        print("+" + "=" * 68 + "+")
        print("|          PlcSentinel - INDUSTRIAL SCADA/HMI SUPERVISOR             |")
        print("|           Target: OpenPLC Runtime (127.0.0.1:502)                  |")
        print("+" + "=" * 68 + "+")
        print(f"|  STATUS: ONLINE   |  POLLS: {self.poll_count:06d}  |  ERRORS: {self.error_count:02d}  |  SCAN: 50ms        |")
        print("+" + "-" * 68 + "+")
        print("|  [PROCESS TANK LEVEL MONITOR]                                      |")
        print(f"|  Level: [{bar}] {level_pct:5.1f}% ({level_val:4d}/1000)   |")
        print("|                                                                    |")
        print(f"|  Safe Low Limit:  {low_thresh/10.0:5.1f}% ({low_thresh:04d})     Safe High Limit: {high_thresh/10.0:5.1f}% ({high_thresh:04d})  |")
        print("+" + "-" * 68 + "+")
        print("|  [ACTUATOR ANNUNCIATOR PANEL]                                      |")
        print(f"|  Inflow Pump (%QX0.0) : [{'RUNNING (ON)' if pump_on else 'STOPPED(OFF)':^14}]                                 |")
        print(f"|  Drain Valve (%QX0.1) : [{'OPEN (DRAIN)' if drain_open else 'CLOSED(SAFE)':^14}]                                 |")
        print(f"|  Alarm Beacon(%QX0.2) : [{'CRITICAL' if alarm_on else 'NORMAL':^14}]                                 |")
        print(f"|  Control Mode(%QX0.3) : [{'MANUAL OVERRIDE' if manual_mode else 'AUTOMATIC':^14}]                                 |")
        print("+" + "=" * 68 + "+")

    def run_hmi(self, duration_sec=5, interval=0.5):
        if not self.client.connect():
            print(f"[!] Cannot connect to OpenPLC at {self.host}:{self.port}")
            return

        end_time = time.time() + duration_sec
        try:
            while time.time() < end_time:
                self.poll_count += 1
                coils_res = self.client.read_coils(address=0, count=4, device_id=1)
                regs_res = self.client.read_holding_registers(address=0, count=4, device_id=1)

                if coils_res.isError() or regs_res.isError():
                    self.error_count += 1
                else:
                    coils = coils_res.bits[:4]
                    holding_regs = regs_res.registers
                    level_val = holding_regs[2] if len(holding_regs) > 2 else 0
                    self.draw_screen(coils, holding_regs, level_val)

                time.sleep(interval)
        finally:
            self.client.close()

if __name__ == "__main__":
    hmi = IndustrialHMI()
    hmi.run_hmi(duration_sec=3, interval=0.5)
