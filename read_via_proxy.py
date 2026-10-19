#!/usr/bin/env python3
"""
PlcSentinel - Quick Telemetry Reader via DPI Proxy (Port 5020)
"""

from pymodbus.client import ModbusTcpClient

def main():
    print("[*] Connecting to Modbus L7 DPI Proxy on 127.0.0.1:5020...")
    client = ModbusTcpClient("127.0.0.1", port=5020)
    if not client.connect():
        print("[!] Connection failed. Ensure modbus_dpi_proxy.py is running.")
        return

    # Read Holding Registers 0 & 1 (Thresholds)
    res_regs = client.read_holding_registers(address=0, count=2, device_id=1)
    
    # Read Coils 0 through 3 (Actuators)
    res_coils = client.read_coils(address=0, count=4, device_id=1)

    if not res_regs.isError() and not res_coils.isError():
        high_th, low_th = res_regs.registers[0], res_regs.registers[1]
        pump, drain, alarm, mode = res_coils.bits[:4]

        print("\n[+] TELEMETRY RECEIVED (VIA DPI PROXY):")
        print(f"    - High Threshold Setpoint: {high_th} ({high_th/10.0:.1f}%)")
        print(f"    - Low Threshold Setpoint : {low_th} ({low_th/10.0:.1f}%)")
        print(f"    - Pump Motor Contactor   : {'ON' if pump else 'OFF'}")
        print(f"    - Emergency Drain Valve  : {'OPEN' if drain else 'CLOSED'}")
        print(f"    - Alarm Beacon           : {'ALERT' if alarm else 'NORMAL'}")
        print(f"    - Control Mode           : {'MANUAL' if mode else 'AUTO'}")
    else:
        print(f"[!] Error reading registers: {res_regs}")

    client.close()

if __name__ == "__main__":
    main()
