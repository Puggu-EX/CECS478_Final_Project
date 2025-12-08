import socket
import time
import os

PROXY_HOST = os.environ.get("PROXY_HOST", "proxy")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8000"))


def main():
    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_HOST, PROXY_PORT))
        print(f"[client] Connected to proxy at {PROXY_HOST}:{PROXY_PORT}")
        s.sendall(b"hello from client!\n")
        resp = s.recv(4096)
        if not resp == None:
            print(f"[client] Got response: {resp!r}")
        else:
            print(f"Didnt get anything back")


if __name__ == "__main__":
    main()
