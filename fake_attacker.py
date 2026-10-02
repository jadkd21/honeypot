#!/usr/bin/env python3
"""
Fake attacker - test client for the honeypot.
Simulates what a Mirai-style botnet does: knock on the Telnet port
and try common default credentials.

Target is YOUR OWN machine (127.0.0.1) only. This exists so you can
watch your honeypot catch an attacker without needing a real one.
"""

import socket
import time

TARGET = "127.0.0.1"
PORT = 2323

# The classic IoT default credentials botnets try first
CREDENTIALS = [
    ("admin", "admin"),
    ("root", "12345"),
    ("admin", "password"),
    ("guest", "guest"),
    ("root", "root"),
]


def read_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


def main():
    print("Simulating botnet attack against your own honeypot...\n")
    for user, pwd in CREDENTIALS:
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((TARGET, PORT))
            read_until(s, b"login: ")
            s.sendall(user.encode() + b"\n")
            read_until(s, b"Password: ")
            s.sendall(pwd.encode() + b"\n")
            resp = read_until(s, b"Access denied.")
            print(f"  tried {user} / {pwd}  -> denied (as expected)")
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"  could not reach honeypot: {e}")
            print("  Is honeypot.py running in the other window?")
            return
        finally:
            s.close()
        time.sleep(0.3)
    print("\nDone. Check the honeypot window - it caught all 5.")


if __name__ == "__main__":
    main()
