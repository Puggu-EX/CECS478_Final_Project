import socket
import time
import random

PROXY_HOST = "proxy"
PROXY_PORT = 8000


def main():
    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_HOST, PROXY_PORT))
        print(f"[client] Connected to proxy at {PROXY_HOST}:{PROXY_PORT}", flush=True)

        while True:
            random_value = random.randint(0, 150)
            random_value = random.choice(
                [
                    "Hello!",
                    "Safe!",
                    "No harm!",
                    "Hi!",
                    "This is a malicous message! You can tell by the odd size!",
                ]
            )
            s.sendall(f"{random_value}\n".encode())
            print(f"[client] Sent: {random_value}", flush=True)

            response = s.recv(4096)
            if not response:
                print("[client] Connection closed by proxy/server", flush=True)
                break

            time.sleep(2)
            decoded = response.decode().strip()
            print(f"[client] Got response: \n\t{decoded}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
