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
            s.sendall(f"{random_value}".encode())
            time.sleep(1)

            response = s.recv(4096)
            if response == None:
                print(f"Didnt get anything back. Something might be wrong")
                exit(0)

            print(f"[client] Got response: \n\t{response!r}")

            time.sleep(10)


if __name__ == "__main__":
    main()
