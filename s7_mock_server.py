#!/usr/bin/env python3
"""
PlcSentinel - Local Siemens S7 Mock Server (Snap7 Server)
Simulates a Siemens Simatic S7 PLC (S7-300 / S7-1200) locally on port 1102:
- Registers DB1 with sample process variables
- Registers Memory Marker Area (Area.MK)
- Supports S7comm Read/Write jobs and CPU status queries
"""

import time
import logging
import snap7
from snap7.server import Server
from snap7.util import set_int, set_real, set_bool

logging.basicConfig(level=logging.INFO, format="%(asctime)s [S7-MOCK-SERVER] %(message)s")
logger = logging.getLogger("S7MockServer")

def run_mock_s7_server(port=1102):
    server = Server()

    # 1. Allocate & Initialize DB1 memory (100 bytes)
    db1_data = bytearray(100)
    set_int(db1_data, 0, 850)      # DBW0: High Setpoint = 850 (85.0%)
    set_int(db1_data, 2, 200)      # DBW2: Low Setpoint = 200 (20.0%)
    set_real(db1_data, 4, 45.2)    # DBD4: Liquid Flow Rate = 45.2 L/min
    set_bool(db1_data, 8, 0, True) # DBX8.0: Pump Motor Active (True)
    set_bool(db1_data, 8, 1, False)# DBX8.1: Alarm Inactive (False)

    # 2. Allocate & Initialize Memory Marker area (Area.MK)
    mk_data = bytearray(64)
    set_bool(mk_data, 0, 0, True)  # M0.0: System Ready
    set_bool(mk_data, 0, 1, False) # M0.1: Maintenance Mode

    # Register areas with Snap7 server
    server.register_area(snap7.SrvArea.DB, 1, db1_data)
    server.register_area(snap7.SrvArea.MK, 0, mk_data)

    logger.info(f"Starting Siemens S7 Mock Controller on 127.0.0.1:{port}...")
    server.start_to("127.0.0.1", tcp_port=port)
    logger.info("Mock Controller is in RUN mode. Ready for S7comm client connections.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down mock S7 server.")
    finally:
        server.stop()
        server.destroy()

if __name__ == "__main__":
    run_mock_s7_server(port=1102)
