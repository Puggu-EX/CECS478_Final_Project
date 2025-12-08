import socket
import threading
import os

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8000"))
TARGET_HOST = os.environ.get("TARGET_HOST", "server")  # docker service name
TARGET_PORT = int(os.environ.get("TARGET_PORT", "9000"))


def pipe(src, dst, label):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                # remote side closed
                break
            dst.sendall(data)
    except (ConnectionResetError, OSError) as e:
        print(f"[proxy] {label} pipe closed: {e}")
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        src.close()
        dst.close()


def handle_client(client_sock, client_addr):
    print(f"[proxy] New client from {client_addr}")

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.connect((TARGET_HOST, TARGET_PORT))
    print(f"[proxy] Connected upstream to {TARGET_HOST}:{TARGET_PORT}")

    t1 = threading.Thread(
        target=pipe, args=(client_sock, upstream, "c->s"), daemon=True
    )
    t2 = threading.Thread(
        target=pipe, args=(upstream, client_sock, "s->c"), daemon=True
    )
    t1.start()
    t2.start()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen()
        print(
            f"[proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}, forwarding to {TARGET_HOST}:{TARGET_PORT}"
        )

        while True:
            client_sock, addr = s.accept()
            threading.Thread(
                target=handle_client, args=(client_sock, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
