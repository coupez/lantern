#!/usr/bin/env python3
"""Exercise Lantern through a real ADB server and a synthetic adbd transport.

This is intentionally container-only.  It tests ADB host-server transport
selection and shell-v2 stream bridging; it does not emulate Android getprop,
authentication, USB, pairing, or a physical device.
"""

import argparse
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

CNXN = 0x4E584E43
OPEN = 0x4E45504F
OKAY = 0x59414B4F
WRTE = 0x45545257
CLSE = 0x45534C43
COMMAND = ("/system/bin/getprop ro.product.manufacturer && "
           "/system/bin/getprop ro.product.model && "
           "/system/bin/getprop ro.product.device && "
           "/system/bin/getprop ro.build.fingerprint")
PROPERTIES = b"Synthetic Maker\nSynthetic Model\nsynthetic_device\nsynthetic/device:14/test\n"


def recv_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise RuntimeError("truncated ADB transport packet")
        out.extend(chunk)
    return bytes(out)


def checksum(data):
    return sum(data) & 0xFFFFFFFF


def send_packet(sock, command, arg0, arg1, data=b""):
    header = struct.pack("<6I", command, arg0, arg1, len(data),
                         checksum(data), command ^ 0xFFFFFFFF)
    sock.sendall(header + data)


def recv_packet(sock):
    words = struct.unpack("<6I", recv_exact(sock, 24))
    command, arg0, arg1, length, check, magic = words
    if length > 65536 or magic != command ^ 0xFFFFFFFF:
        raise RuntimeError("invalid ADB transport header")
    data = recv_exact(sock, length)
    # Since 0x01000001 a sender may omit checksums during initial negotiation.
    # We reply with 0x01000000, which selects classic checksums thereafter.
    skipped_initial_checksum = command == CNXN and arg0 >= 0x01000001 and check == 0
    if checksum(data) != check and not skipped_initial_checksum:
        raise RuntimeError("invalid ADB transport checksum")
    return command, arg0, arg1, data


def shell_frame(channel, data):
    return bytes([channel]) + struct.pack("<I", len(data)) + data


class SyntheticAdbd:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.conn = None
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        try:
            conn, _ = self.listener.accept()
            self.conn = conn
            with conn:
                conn.settimeout(10)
                command, _, _, _ = recv_packet(conn)
                if command != CNXN:
                    raise RuntimeError("ADB host did not begin with CNXN")
                banner = (b"device::ro.product.name=synthetic;"
                          b"ro.product.model=Synthetic_Model;"
                          b"ro.product.device=synthetic_device;features=shell_v2;\0")
                send_packet(conn, CNXN, 0x01000000, 4096, banner)
                for remote_id in (1, 2):
                    command, local_id, _, payload = recv_packet(conn)
                    if command != OPEN:
                        raise RuntimeError("expected ADB OPEN")
                    service = payload.rstrip(b"\0").decode("ascii")
                    expected = "shell,v2,raw:" + COMMAND
                    if service != expected:
                        raise RuntimeError("unexpected OPEN service: " + service)
                    send_packet(conn, OKAY, remote_id, local_id)
                    stream = shell_frame(1, PROPERTIES) + shell_frame(3, b"\0")
                    send_packet(conn, WRTE, remote_id, local_id, stream)
                    command, arg0, arg1, _ = recv_packet(conn)
                    if command != OKAY or arg0 != local_id or arg1 != remote_id:
                        raise RuntimeError("missing host WRTE acknowledgement")
                    send_packet(conn, CLSE, remote_id, local_id)
                    command, arg0, arg1, _ = recv_packet(conn)
                    if command != CLSE or arg0 != local_id or arg1 != remote_id:
                        raise RuntimeError("missing host CLSE acknowledgement")
        except Exception as exc:  # surfaced on the main thread
            self.error = exc
        finally:
            self.conn = None
            self.listener.close()

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass
        conn = self.conn
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_checked(argv, env, timeout=10):
    return subprocess.run(argv, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=True)


def main():
    if platform.system() != "Linux" or os.environ.get("LANTERN_ISOLATED_ADB_TEST") != "1":
        raise SystemExit("refusing: run only in isolated Linux Docker with LANTERN_ISOLATED_ADB_TEST=1")
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="/tmp/lantern")
    parser.add_argument("--adb", default=shutil.which("adb"))
    args = parser.parse_args()
    if not args.adb or not os.path.isfile(args.binary):
        raise SystemExit("adb and compiled Lantern binary are required")

    adbd = SyntheticAdbd()
    adbd.start()
    server_port = free_port()
    env = os.environ.copy()
    env["ADB_MDNS_AUTO_CONNECT"] = ""
    env["ADB_LOCAL_TRANSPORT_MAX_PORT"] = "0"
    # Docker supplies an isolated HOME; deliberately do not replace HOME.
    with tempfile.TemporaryDirectory(prefix="lantern-adb-interop-") as temp:
        log = open(os.path.join(temp, "adb-server.log"), "w", encoding="utf-8")
        # Older packaged adb accepts tcp:PORT here; without -a its listener
        # binds loopback. Client requests below still use explicit host+port.
        server = subprocess.Popen(
            [args.adb, "-L", f"tcp:{server_port}", "server", "nodaemon"],
            env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            text=True)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    # ADB `version` is client-local. Probe this owned listener
                    # directly so a later command cannot silently start one.
                    with socket.create_connection(("127.0.0.1", server_port), timeout=0.2):
                        pass
                    break
                except OSError:
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("isolated ADB server did not become ready")
                    time.sleep(0.05)

            run_checked([args.adb, "-H", "127.0.0.1", "-P", str(server_port),
                         "connect", f"127.0.0.1:{adbd.port}"], env)
            devices = run_checked([args.adb, "-H", "127.0.0.1", "-P", str(server_port),
                                   "devices", "-l"], env).stdout.splitlines()
            rows = [line for line in devices if " transport_id:" in line]
            if len(rows) != 1 or " device " not in (" " + rows[0] + " "):
                raise RuntimeError("expected exactly one online synthetic transport")
            transport = rows[0].rsplit(" transport_id:", 1)[1].strip()
            if not transport.isdigit() or int(transport) <= 0:
                raise RuntimeError("invalid synthetic transport ID")

            base = [args.binary, "android", "--transport-id", transport,
                    "--server", f"127.0.0.1:{server_port}", "--timeout", "5s"]
            structured = run_checked(base + ["--json"], env).stdout
            report = json.loads(structured)
            props = report.get("properties", {})
            expected = {"manufacturer": "Synthetic Maker", "model": "Synthetic Model",
                        "device": "synthetic_device", "build_fingerprint": "synthetic/device:14/test"}
            if report.get("complete") is not True or props != expected:
                raise RuntimeError("Lantern JSON did not retain the four synthetic properties")
            if report.get("source") != "adb" or report.get("server") != f"127.0.0.1:{server_port}" or report.get("transport_id") != int(transport):
                raise RuntimeError("Lantern JSON provenance mismatch")
            keys = {claim.get("key") for claim in report.get("claims", [])}
            if keys != {"ro.product.manufacturer", "ro.product.model", "ro.product.device", "ro.build.fingerprint"}:
                raise RuntimeError("Lantern JSON claim keys mismatch")
            plain = run_checked(base, env).stdout
            for value in expected.values():
                if value not in plain:
                    raise RuntimeError("Lantern plain output omitted a synthetic property")
            for output in (structured, plain):
                if f"127.0.0.1:{adbd.port}" in output or "serial" in output.lower():
                    raise RuntimeError("transport address/serial leaked into Lantern output")
            adbd.thread.join(10)
            if adbd.thread.is_alive() or adbd.error:
                raise RuntimeError(f"synthetic adbd failed: {adbd.error}")
            print("Android ADB interop PASS (real isolated ADB server; synthetic adbd)")
        finally:
            adbd.close()
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)
            log.close()
            adbd.thread.join(timeout=3)


if __name__ == "__main__":
    main()
