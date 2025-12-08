import socket
import os

HOST = "0.0.0.0"
PORT = int(os.environ.get("SERVER_PORT", "9000"))  # match whatever proxy connects to


def handle_client(conn, addr):
    print(f"[server] Connection from {addr}", flush=True)
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                # b"" means the other side closed the connection
                print("[server] Client closed connection", flush=True)
                break

            text = data.decode().strip()
            print(f"[server] Received raw data: {text!r}", flush=True)

            value = int(text)
            response = f"[server] got {value}\n"

            print(f"[server] Sending response: {response!r}", flush=True)
            conn.sendall(response.encode())


def main():
    print(f"[server] Listening on {HOST}:{PORT}", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
