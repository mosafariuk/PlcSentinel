#!/usr/bin/env python3
"""
PlcSentinel - Industrial Protocol Security Comparative Assessment
Direct comparative analysis of Legacy Modbus TCP vs Modern Encrypted OPC UA (IEC 62541).
Evaluates security controls against IEC 62443-4-2 Foundational Requirements.
"""

def print_comparison():
    print("+" + "=" * 78 + "+")
    print("|      INDUSTRIAL PROTOCOL SECURITY MATRIX: MODBUS TCP vs. OPC UA (IEC 62541)  |")
    print("+" + "=" * 78 + "+")
    print(f"| {'SECURITY VECTOR':<24} | {'MODBUS TCP (Legacy OT)':<24} | {'OPC UA (IEC 62541)':<24} |")
    print("+" + "-" * 78 + "+")
    print(f"| {'Port & Transport':<24} | {'Port 502 / Raw TCP':<24} | {'Port 4840 / TCP Binary':<24} |")
    print(f"| {'Authentication (FR 1)':<24} | {'NONE (Unauthenticated)':<24} | {'X.509 Mutual PKI / User':<24} |")
    print(f"| {'Access Control (FR 2)':<24} | {'Any client can write':<24} | {'Node-level ACLs & Roles':<24} |")
    print(f"| {'Integrity (FR 3)':<24} | {'None (TCP checksum only)':<24} | {'RSA/HMAC-SHA256 Signing':<24} |")
    print(f"| {'Confidentiality (FR 4)':<24} | {'PLAINTEXT (Sniffable)':<24} | {'AES-256-CBC Encryption':<24} |")
    print(f"| {'Replay Protection':<24} | {'Vulnerable (No Nonce)':<24} | {'Sequence IDs & Nonces':<24} |")
    print(f"| {'IEC 62443 Max SL':<24} | {'SL 1 (Requires Gateway)':<24} | {'SL 3 / SL 4 Native':<24} |")
    print(f"| {'Wire Overhead':<24} | {'Minimal (7-byte MBAP)':<24} | {'Higher (Cryptographic)':<24} |")
    print("+" + "=" * 78 + "+")
    print("\n[+] SECURITY IMPLICATION SUMMARY:")
    print("1. Modbus TCP has ZERO cryptographic defenses. An attacker on the local VLAN")
    print("   can effortlessly sniff process variables, alter setpoints, and force coils.")
    print("   Mitigation requires external Layer-7 DPI Proxies (like modbus_dpi_proxy.py).")
    print("\n2. OPC UA (Basic256Sha256) provides native end-to-end security:")
    print("   Wire-tapping yields only AES-256 ciphertext. Attackers cannot forge writes")
    print("   or inject unauthorized commands without possessing the valid client private key.")
    print("+" + "=" * 78 + "+")

if __name__ == "__main__":
    print_comparison()
