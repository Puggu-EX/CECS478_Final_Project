import socket
import time
import os
import random

PROXY_HOST = os.environ.get("PROXY_HOST", "proxy")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8000"))


def main():
    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_HOST, PROXY_PORT))
        print(f"[client] Connected to proxy at {PROXY_HOST}:{PROXY_PORT}")

        while True:
            random_value = random.randint(10, 99)
            s.sendall(f"{random_value}\n".encode())
            print(f"[client] Sent: {random_value}")

            response = s.recv(4096)
            if not response:
                print("[client] Connection closed by proxy/server")
                break

            time.sleep(1)
            print(f"[client] Got response: \n\t{response!r}")
            time.sleep(10)


if __name__ == "__main__":
    main()
