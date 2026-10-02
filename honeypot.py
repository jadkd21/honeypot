#!/usr/bin/env python3
"""
Honeypot - fake Telnet server
Listens on port 2323 pretending to be a vulnerable smart router.
Every login attempt gets logged: time, attacker IP, username, password.

This is defensive: it never attacks anything, it just listens and logs.
Real botnets (like Mirai, which hijacked thousands of cameras and routers)
hunt for exactly this kind of open Telnet service.

How to run:
    python honeypot.py          (one window)
    python fake_attacker.py     (second window - simulates the botnet)

Press Ctrl+C to stop and see the summary.
"""

import socket
import threading
import sys
from datetime import datetime
from collections import Counter

HOST = "0.0.0.0"
PORT = 2323
LOGFILE = "honeypot.log"
MAX_TRIES = 3

BANNER = b"\r\nM3000 Smart Router\r\nFirmware v2.1.4\r\n\r\n"

attempts = []  # (ip, username, password)
lock = threading.Lock()


def log_attempt(ip, username, password):
    """Write the attempt to the log file and the screen."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with lock:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} | {ip} | {username} | {password}\n")
        attempts.append((ip, username, password))
    print(f"  [!] {ts}  {ip:15} tried  {username} / {password}", flush=True)


def recv_line(conn):
    """Read one line of text from the socket."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
        if len(data) > 128:
            break
    return data.decode("utf-8", errors="replace").strip()


def handle(conn, addr):
    """Play the role of a gullible router for one attacker."""
    ip = addr[0]
    try:
        conn.settimeout(30)
        conn.sendall(BANNER)
        for _ in range(MAX_TRIES):
            conn.sendall(b"login: ")
            username = recv_line(conn)
            if not username:
                break
            conn.sendall(b"Password: ")
            password = recv_line(conn)
            log_attempt(ip, username, password)
            conn.sendall(b"\r\nAccess denied.\r\n\r\n")
    except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        pass
    finally:
        conn.close()


def main():
    print("=" * 70)
    print("  HONEYPOT - fake Telnet server on port 2323")
    print("=" * 70)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((HOST, PORT))
    except OSError:
        print(f"\n  Port {PORT} is busy - is another honeypot already running?")
        sys.exit(1)
    srv.listen(20)

    print(f"\n  Listening... press Ctrl+C to stop")
    print(f"  Attempts are logged to {LOGFILE}\n")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()

    print("\n" + "-" * 70)
    print(f"  Caught {len(attempts)} login attempts.")
    if attempts:
        ips = Counter(a[0] for a in attempts)
        users = Counter(a[1] for a in attempts)
        pwds = Counter(a[2] for a in attempts)
        print(f"  Unique attacker IPs : {len(ips)}")
        print(f"  Top usernames       : {', '.join(u for u, _ in users.most_common(5))}")
        print(f"  Top passwords       : {', '.join(p for p, _ in pwds.most_common(5))}")
    print(f"\n  Full log: {LOGFILE}  <- the log analyzer reads this next.")


if __name__ == "__main__":
    main()
