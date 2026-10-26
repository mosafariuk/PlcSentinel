#!/usr/bin/env python3
"""
S7-Sentinel: Siemens Simatic S7 Assessment & Telemetry Client
Author: Senior ICS/OT Cybersecurity Specialist
Protocol: S7comm over ISO-on-TCP (RFC 1006 / TCP Port 102)
Target Controllers: Siemens S7-300, S7-400, S7-1200, S7-1500

Security Context:
- S7comm (legacy S7-300/400 and S7-1200/1500 with 'Permit access with PUT/GET') 
  operates without transport-layer authentication or encryption.
- This tool implements non-destructive read assessment and validated setpoint
  writing adhering to safe OT operational boundaries.
"""

import sys
import time
import logging
from typing import Optional, Dict, Any, Tuple

try:
    import snap7
    from snap7 import Area, WordLen
    from snap7.client import Client
    from snap7.util import (
        get_bool, set_bool,
        get_int, set_int,
        get_real, set_real,
        get_dint, set_dint,
        get_string
    )
except ImportError as e:
    print(f"[!] Critical Import Failure: {e}")
    print("[!] Install the library via: pip install python-snap7")
    sys.exit(1)

# Configure structured OT logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [S7-SENTINEL] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("S7Sentinel")


class S7Sentinel:
    """
    Industrial Security Assessment & Telemetry Client for Siemens S7 PLCs.
    """

    def __init__(
        self,
        ip: str = "127.0.0.1",
        rack: int = 0,
        slot: int = 1,
        tcp_port: int = 102,
        timeout_ms: int = 3000
    ):
        """
        Initialize S7-Sentinel client.
        
        Rack and Slot Hardware Conventions:
        - S7-300 / ET200:   Rack 0, Slot 2
        - S7-400:          Rack 0, Slot depends on configuration (usually 2 or 3)
        - S7-1200 / 1500:  Rack 0, Slot 1
        - WinSPS / PLCSIM: Rack 0, Slot 2 (or Slot 1)
        """
        self.ip = ip
        self.rack = rack
        self.slot = slot
        self.tcp_port = tcp_port
        self.timeout_ms = timeout_ms
        self.client = Client()

    def connect(self) -> bool:
        """
        Establishes ISO-on-TCP connection (RFC 1006) and completes the
        S7comm Communication Setup (Negotiate PDU length).
        """
        logger.info(f"Initiating connection to Siemens PLC at {self.ip}:{self.tcp_port} (Rack {self.rack}, Slot {self.slot})...")
        try:
            # Set connection parameters / timeout
            self.client.set_param(snap7.client.Parameter.PingTimeout, self.timeout_ms)
            self.client.set_param(snap7.client.Parameter.SendTimeout, self.timeout_ms)
            self.client.set_param(snap7.client.Parameter.RecvTimeout, self.timeout_ms)

            self.client.connect(self.ip, self.rack, self.slot, tcp_port=self.tcp_port)
            if self.client.get_connected():
                logger.info(f"[+] Successfully established S7comm session with {self.ip}:{self.tcp_port}")
                return True
            else:
                logger.error(f"[-] Handshake failed: Client not connected to {self.ip}")
                return False
        except Exception as ex:
            logger.error(f"[-] Connection Error to {self.ip}:{self.tcp_port}: {ex}")
            return False

    def disconnect(self):
        """Terminates S7comm session and tears down the TCP socket."""
        try:
            if self.client.get_connected():
                self.client.disconnect()
                logger.info("[*] Disconnected cleanly from Siemens PLC.")
        except Exception as ex:
            logger.warning(f"[!] Warning during disconnect: {ex}")

    def get_cpu_status(self) -> str:
        """
        Queries PLC Operating Mode (Run, Stop, or Unknown).
        Function: cli_get_cpu_state() -> returns state string
        """
        if not self.client.get_connected():
            logger.error("Cannot query CPU status: Client is disconnected.")
            return "DISCONNECTED"

        try:
            state = self.client.get_cpu_state()
            logger.info(f"PLC CPU Operating Status: {state}")
            return state
        except Exception as ex:
            logger.error(f"Failed to retrieve CPU state: {ex}")
            return "ERROR"

    def read_datablock_parameters(
        self,
        db_number: int = 1,
        start_offset: int = 0,
        byte_length: int = 16
    ) -> Optional[bytearray]:
        """
        Reads a contiguous slice of Data Block (DB) memory.
        
        Args:
            db_number: Target Data Block number (e.g. 1 for DB1)
            start_offset: Byte offset within DB (e.g. 0 for DBB0)
            byte_length: Total number of bytes to read
        """
        if not self.client.get_connected():
            logger.error("Read DB failed: Client is not connected.")
            return None

        try:
            logger.info(f"Reading DB{db_number} from offset {start_offset} (length: {byte_length} bytes)...")
            data = self.client.db_read(db_number, start_offset, byte_length)
            hex_dump = " ".join(f"{b:02X}" for b in data)
            logger.info(f"DB{db_number}.DBB{start_offset} Raw Payload: {hex_dump}")
            return data
        except Exception as ex:
            logger.error(f"Failed reading DB{db_number}: {ex}")
            return None

    def read_memory_markers(
        self,
        start_byte: int = 0,
        byte_length: int = 4
    ) -> Optional[bytearray]:
        """
        Reads internal Merker / Memory Marker area (Area.MK / %M memory).
        Used extensively in S7 ladder logic for internal relay flags and status words.
        """
        if not self.client.get_connected():
            logger.error("Read Merkers failed: Client is not connected.")
            return None

        try:
            logger.info(f"Reading Memory Markers Area (Area.MK) from MB{start_byte} (length: {byte_length} bytes)...")
            data = self.client.read_area(Area.MK, 0, start_byte, byte_length)
            hex_dump = " ".join(f"{b:02X}" for b in data)
            logger.info(f"MB{start_byte} Raw Payload: {hex_dump}")
            return data
        except Exception as ex:
            logger.error(f"Failed reading Memory Markers (Area.MK): {ex}")
            return None

    def parse_process_data(self, raw_db_data: bytearray) -> Dict[str, Any]:
        """
        Parses raw bytes into structured industrial telemetry using snap7.util.
        Example mapping:
        - DBW0 (Offset 0, 2 bytes): High Setpoint (INT)
        - DBW2 (Offset 2, 2 bytes): Low Setpoint (INT)
        - DBD4 (Offset 4, 4 bytes): Tank Flow Rate (REAL / Float)
        - DBX8.0 (Offset 8, Bit 0): Inflow Pump Run Feedback (BOOL)
        - DBX8.1 (Offset 8, Bit 1): High Level Alarm Strobe (BOOL)
        """
        if not raw_db_data or len(raw_db_data) < 10:
            logger.warning("Data buffer too short to parse standard telemetry layout.")
            return {}

        parsed = {
            "HighSetpoint": get_int(raw_db_data, 0),
            "LowSetpoint": get_int(raw_db_data, 2),
            "FlowRate": get_real(raw_db_data, 4),
            "PumpRunning": get_bool(raw_db_data, 8, 0),
            "AlarmActive": get_bool(raw_db_data, 8, 1),
        }
        return parsed

    def write_safe_setpoint(
        self,
        db_number: int,
        byte_offset: int,
        new_value: int,
        min_allowed: int = 100,
        max_allowed: int = 900
    ) -> bool:
        """
        Performs validated, safe writing of a 16-bit Integer setpoint (DBW).
        
        Strict Defensive Controls:
        1. Pre-write boundary check: Rejects values outside [min_allowed, max_allowed].
        2. Non-destructive write: Updates only the targeted 2-byte word.
        3. Read-back verification: Queries the PLC immediately after writing to confirm.
        """
        if not self.client.get_connected():
            logger.error("Write aborted: Client is disconnected.")
            return False

        # 1. Semantic Boundary Enforcement (Input Validation)
        if not (min_allowed <= new_value <= max_allowed):
            logger.error(
                f"[BOUNDARY VIOLATION] Refusing write! Value {new_value} is outside safe operational "
                f"envelope [{min_allowed} .. {max_allowed}]. Prevented potential hazard!"
            )
            return False

        logger.info(f"Targeting DB{db_number}.DBW{byte_offset}: Validated safe value = {new_value}...")
        try:
            # 2. Prepare 2-byte buffer with big-endian 16-bit signed integer
            buffer = bytearray(2)
            set_int(buffer, 0, new_value)

            # 3. Issue S7comm Write Job
            self.client.db_write(db_number, byte_offset, buffer)
            logger.info(f"[+] S7comm Write command executed successfully for DB{db_number}.DBW{byte_offset}.")

            # 4. Read-back verification
            time.sleep(0.05)
            verify_buffer = self.client.db_read(db_number, byte_offset, 2)
            actual_value = get_int(verify_buffer, 0)

            if actual_value == new_value:
                logger.info(f"[+] Read-back verification PASSED: DB{db_number}.DBW{byte_offset} = {actual_value}")
                return True
            else:
                logger.error(f"[-] Read-back verification FAILED: Expected {new_value}, read {actual_value}")
                return False

        except Exception as ex:
            logger.error(f"[-] Exception occurred during S7comm write: {ex}")
            return False


# ==============================================================================
# Execution Entry Point & Demonstration
# ==============================================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="S7-Sentinel: Siemens S7comm Assessment Tool")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="Target PLC IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=102, help="ISO-on-TCP Port (default: 102, or 1102 for local mock)")
    parser.add_argument("--rack", type=int, default=0, help="PLC Rack number (default: 0)")
    parser.add_argument("--slot", type=int, default=1, help="PLC Slot number (default: 1 for S7-1200/1500, 2 for S7-300)")
    args = parser.parse_args()

    sentinel = S7Sentinel(ip=args.ip, rack=args.rack, slot=args.slot, tcp_port=args.port)

    if sentinel.connect():
        try:
            # 1. Check CPU Operating Mode
            cpu_status = sentinel.get_cpu_status()

            # 2. Read DB1 Process Parameters (e.g., 16 bytes)
            db1_data = sentinel.read_datablock_parameters(db_number=1, start_offset=0, byte_length=16)
            if db1_data:
                telemetry = sentinel.parse_process_data(db1_data)
                logger.info(f"Decoded Telemetry from DB1: {telemetry}")

            # 3. Read Memory Markers (Area.MK)
            m_data = sentinel.read_memory_markers(start_byte=0, byte_length=4)

            # 4. Perform Safe Setpoint Update (Validated range 100 .. 900)
            sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=820, min_allowed=100, max_allowed=900)

            # 5. Demonstrate Boundary Protection (Will be blocked)
            sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=9999, min_allowed=100, max_allowed=900)

        finally:
            sentinel.disconnect()
