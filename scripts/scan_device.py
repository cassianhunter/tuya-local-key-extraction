#!/usr/bin/env python3
"""
Scan for Tuya devices on the local network.
Listens on UDP 6666 (plaintext, protocol 3.1) and 6667 (encrypted, protocol 3.3+).
Also attempts a direct TCP probe on the known device IP.
"""

import argparse
import asyncio
import json
import socket
import struct
from hashlib import md5
try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES

# Universal Tuya UDP broadcast decryption key
UDPKEY = md5(b"yGAdlopoPVldABfn").digest()
TCP_PORT = 6668


def unpad(s: bytes) -> bytes:
    return s[: -s[-1]]


def decrypt_udp(data: bytes) -> str:
    """Decrypt a Tuya UDP broadcast payload."""
    payload = data[20:-8]  # Strip 20-byte header and 8-byte footer
    try:
        cipher = AES.new(UDPKEY, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(payload))
        return decrypted.decode("utf-8")
    except Exception:
        # Might be plaintext (protocol 3.1 on port 6666)
        try:
            return payload.decode("utf-8")
        except Exception:
            return payload.hex()


class TuyaUDPListener(asyncio.DatagramProtocol):
    def __init__(self, port: int, results: dict, target_ip: str | None):
        self.port = port
        self.results = results
        self.target_ip = target_ip

    def datagram_received(self, data: bytes, addr: tuple):
        ip = addr[0]
        if ip in self.results:
            return  # Already seen this device

        decoded = decrypt_udp(data)
        try:
            info = json.loads(decoded)
        except json.JSONDecodeError:
            info = {"raw": decoded}

        self.results[ip] = info
        marker = " <<<< TARGET DEVICE" if ip == self.target_ip else ""
        print(f"\n{'='*60}")
        print(f"  Device found at {ip}:{self.port}{marker}")
        print(f"{'='*60}")
        print(json.dumps(info, indent=2))


def tcp_probe(ip: str, port: int = TCP_PORT, timeout: float = 5.0) -> bool:
    """Check if TCP port 6668 is open on the device."""
    print(f"\nProbing TCP {ip}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"  TCP {port} is OPEN — confirmed Tuya device!")
            # Try to receive any initial data
            try:
                sock.settimeout(2)
                data = sock.recv(1024)
                if data:
                    print(f"  Received {len(data)} bytes: {data[:40].hex()}...")
                else:
                    print("  No initial data (expected for 3.4+ protocol)")
            except socket.timeout:
                print("  No initial data (expected for 3.4+ protocol)")
            return True
        else:
            print(f"  TCP {port} is CLOSED (error code: {result})")
            return False
    except socket.timeout:
        print(f"  TCP {port} connection timed out")
        return False
    except Exception as e:
        print(f"  TCP probe error: {e}")
        return False
    finally:
        sock.close()


async def main():
    parser = argparse.ArgumentParser(description="Scan for Tuya devices on the local network")
    parser.add_argument("--ip", help="Known device IP to highlight in results")
    parser.add_argument("--duration", type=int, default=20, help="Scan duration in seconds (default: 20)")
    args = parser.parse_args()

    print("Tuya Device Scanner")
    if args.ip:
        print(f"Looking for device at {args.ip}")
    print(f"Scanning UDP 6666/6667 for {args.duration} seconds...\n")

    results = {}
    loop = asyncio.get_event_loop()

    transports = []
    for port in (6666, 6667):
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda p=port: TuyaUDPListener(p, results, args.ip),
                local_addr=("0.0.0.0", port),
            )
            transports.append(transport)
            print(f"  Listening on UDP {port}")
        except OSError as e:
            print(f"  Could not bind UDP {port}: {e}")

    # Also do a TCP probe while waiting
    if args.ip:
        tcp_probe(args.ip)

    # Listen for UDP broadcasts
    await asyncio.sleep(args.duration)

    for t in transports:
        t.close()

    print(f"\n{'='*60}")
    print(f"  Scan complete — found {len(results)} device(s)")
    print(f"{'='*60}")

    if args.ip and args.ip in results:
        info = results[args.ip]
        print(f"\n  Target device info:")
        print(f"    Device ID:  {info.get('gwId', 'unknown')}")
        print(f"    Product Key: {info.get('productKey', 'unknown')}")
        print(f"    Version:    {info.get('version', 'unknown')}")
        print(f"    Encrypted:  {info.get('encrypt', 'unknown')}")
    elif results:
        if args.ip:
            print("\n  Target device NOT found, but other devices detected.")
            print("  Verify the IP address is correct.")
    else:
        print("\n  No devices found. Make sure:")
        print("    1. You're on the same network as the device")
        print("    2. The OEM app is NOT actively connected")
        print("    3. UDP broadcast is not blocked by firewall")


if __name__ == "__main__":
    asyncio.run(main())
