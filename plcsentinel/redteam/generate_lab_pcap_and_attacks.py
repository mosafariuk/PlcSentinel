#!/usr/bin/env python3
"""
PlcSentinel - Lab Traffic Recorder & OT Anomaly Generator
Executes structured Day 3 to Day 6 laboratory scenarios against OpenPLC,
generating both standard telemetry cycles and security event simulations,
saving the entire exchange to 'modbus_lab_traffic.pcap' for Wireshark inspection.
"""

import socket
import time
import logging
from scapy.all import IP, TCP, wrpcap
import scapy.contrib.modbus as mb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TrafficGenerator")

class ModbusSessionRecorder:
    def __init__(self, host="127.0.0.1", port=502):
        self.host = host
        self.port = port
        self.trans_id = 1
        self.captured_packets = []
        self.sock = None

    def connect(self):
        logger.info(f"Opening TCP socket to OpenPLC at {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3.0)
        self.sock.connect((self.host, self.port))
        self.client_ip, self.client_port = self.sock.getsockname()
        logger.info(f"Connected from local endpoint {self.client_ip}:{self.client_port}")

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.info("Socket closed.")

    def transceive(self, pdu_req, label="Modbus Request"):
        """Sends a Modbus ADU, records raw bytes as Scapy TCP packets for PCAP export."""
        adu_req = mb.ModbusADURequest(transId=self.trans_id, unitId=1) / pdu_req
        req_bytes = bytes(adu_req)
        
        # Synthesize Scapy IP/TCP packet for Request
        pkt_req = IP(src=self.client_ip, dst=self.host) / TCP(sport=self.client_port, dport=self.port, flags="PA") / req_bytes
        self.captured_packets.append(pkt_req)

        self.sock.sendall(req_bytes)
        logger.info(f"[TX] {label} (TransId={self.trans_id})")

        # Receive Response
        resp_bytes = self.sock.recv(1024)
        if resp_bytes:
            pkt_resp = IP(src=self.host, dst=self.client_ip) / TCP(sport=self.port, dport=self.client_port, flags="PA") / resp_bytes
            self.captured_packets.append(pkt_resp)
            adu_resp = mb.ModbusADUResponse(resp_bytes)
            logger.info(f"[RX] Response received ({len(resp_bytes)} bytes): {adu_resp.summary()}")
        else:
            logger.warning("[RX] No response received.")

        self.trans_id += 1
        time.sleep(0.3)
        return resp_bytes

    def run_day3_baseline_telemetry(self):
        logger.info("=== DAY 3: BASELINE TELEMETRY POLLING ===")
        # 1. Read Discrete Inputs (%IX0.0..%IX0.1) - FC 02
        self.transceive(mb.ModbusPDU02ReadDiscreteInputsRequest(startAddr=0, quantity=4), label="FC02 Read Discrete Inputs")
        
        # 2. Read Coils (%QX0.0..%QX0.3) - FC 01
        self.transceive(mb.ModbusPDU01ReadCoilsRequest(startAddr=0, quantity=4), label="FC01 Read Coils")
        
        # 3. Read Input Registers (%IW0) - FC 04
        self.transceive(mb.ModbusPDU04ReadInputRegistersRequest(startAddr=0, quantity=2), label="FC04 Read Input Registers")
        
        # 4. Read Holding Registers (%QW0..%QW1) - FC 03
        self.transceive(mb.ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=2), label="FC03 Read Holding Registers")

    def run_day4_authorized_operations(self):
        logger.info("=== DAY 4: AUTHORIZED CONTROL & LOGIC ADJUSTMENT ===")
        # Write authorized setpoints: High Threshold = 840 (84.0%), Low Threshold = 210 (21.0%)
        self.transceive(mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=0, registerValue=840), label="FC06 Write Safe High Setpoint")
        self.transceive(mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=1, registerValue=210), label="FC06 Write Safe Low Setpoint")
        
        # Verify changes via FC 03
        self.transceive(mb.ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=2), label="FC03 Verify Updated Setpoints")

    def run_day5_ot_anomalies_and_attacks(self):
        logger.info("=== DAY 5: SIMULATING OT ANOMALIES & ATTACK VECTORS ===")
        
        # Attack Vector 1: Unauthorized Actuator Manipulation (FC 05)
        # Attempt to forcibly open Drain Valve (%QX0.1 / Coil 1)
        logger.warning("[ATTACK SCENARIO 1] Injecting unauthorized Write Single Coil (Drain Valve OPEN)...")
        self.transceive(mb.ModbusPDU05WriteSingleCoilRequest(outputAddr=1, outputValue=0xFF00), label="ATTACK: FC05 Force Drain Valve OPEN")

        # Attack Vector 2: Setpoint Tampering (Physical Boundary Violation)
        # Attempt to write an extreme High Threshold of 9999 (well above physical tank capacity)
        logger.warning("[ATTACK SCENARIO 2] Injecting malicious setpoint (Overfill Condition: 9999)...")
        self.transceive(mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=0, registerValue=9999), label="ATTACK: FC06 Tamper Setpoint to 9999")

        # Attack Vector 3: Memory Reconnaissance / Address Probing
        # Attacker attempts to read unallocated register 0x1F40 (8000 decimal)
        logger.warning("[ATTACK SCENARIO 3] Probing unmapped register (Triggering Modbus Exception 0x02)...")
        self.transceive(mb.ModbusPDU03ReadHoldingRegistersRequest(startAddr=8000, quantity=5), label="ATTACK: FC03 Recon Probing Unmapped Space")

        # Reset thresholds to safe values
        logger.info("[REMEDIATION] Restoring safe operational setpoints...")
        self.transceive(mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=0, registerValue=850), label="FC06 Restore Safe High Setpoint")
        self.transceive(mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=1, registerValue=200), label="FC06 Restore Safe Low Setpoint")

    def save_pcap(self, filename="data/modbus_lab_traffic.pcap"):
        logger.info(f"Saving {len(self.captured_packets)} captured packets to '{filename}'...")
        wrpcap(filename, self.captured_packets)
        logger.info(f"PCAP saved successfully: {filename}")

if __name__ == "__main__":
    recorder = ModbusSessionRecorder(host="127.0.0.1", port=502)
    recorder.connect()
    try:
        recorder.run_day3_baseline_telemetry()
        time.sleep(1)
        recorder.run_day4_authorized_operations()
        time.sleep(1)
        recorder.run_day5_ot_anomalies_and_attacks()
    finally:
        recorder.close()
        recorder.save_pcap("data/modbus_lab_traffic.pcap")
