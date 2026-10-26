#!/usr/bin/env python3
"""
PlcSentinel - Minimal IEC 60870-5-104 mock outstation (RTU)

Enough of the protocol for the DPI gateway to sit in front of it: completes the
STARTDT handshake, acknowledges I-frames with an S-frame, and answers a command
with an ACT-CON I-frame. Not a full RTU; it exists so the lab has a backend to
forward sanitized IEC 104 traffic to.
"""

import asyncio
import logging
import argparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IEC104-MOCK] %(message)s")
logger = logging.getLogger("IEC104Mock")

STARTDT_CON = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
STOPDT_CON = bytes([0x68, 0x04, 0x23, 0x00, 0x00, 0x00])
TESTFR_CON = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info(f"Connection from {peer}")
    recv_count = 0
    buf = b""
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break
            buf += data
            while len(buf) >= 2 and buf[0] == 0x68 and len(buf) >= 2 + buf[1]:
                apdu, buf = buf[:2 + buf[1]], buf[2 + buf[1]:]
                cf1 = apdu[2]
                if cf1 & 0x03 == 0x03:  # U-format: STARTDT/STOPDT/TESTFR ACT -> CON
                    if cf1 & 0x04:
                        writer.write(STARTDT_CON)
                    elif cf1 & 0x10:
                        writer.write(STOPDT_CON)
                    elif cf1 & 0x40:
                        writer.write(TESTFR_CON)
                    await writer.drain()
                elif cf1 & 0x01 == 0:  # I-format: ack with an S-frame
                    recv_count += 1
                    writer.write(bytes([0x68, 0x04, 0x01, 0x00, (recv_count << 1) & 0xFF, (recv_count >> 7) & 0xFF]))
                    await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"Connection closed {peer}")


async def main(bind: str, port: int):
    server = await asyncio.start_server(handle, bind, port)
    logger.info(f"IEC 104 mock outstation on {bind}:{port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PlcSentinel IEC 104 mock outstation")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=24040)
    args = parser.parse_args()
    try:
        asyncio.run(main(args.bind, args.port))
    except KeyboardInterrupt:
        logger.info("Mock outstation stopped.")
