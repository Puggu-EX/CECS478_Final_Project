import socket
import time

SERVER_HOST = "server"
SERVER_PORT = 9000


def main():
    time.sleep(2)  # wait a bit for proxy & server to start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        msg = b"Hello from client\n"
        print(f"[CLIENT] Sending: {msg!r}")
        s.sendall(msg)
        data = s.recv(4096)
        print(f"[CLIENT] Received: {data!r}")


if __name__ == "__main__":
    main()
