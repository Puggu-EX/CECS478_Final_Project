import socket
import threading
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8000
TARGET_HOST = "server"
TARGET_PORT = 9000

LOG_FILE = "/logs/log.txt"

MAX_PACKET_SIZE = 50

MAX_RATE = 5 # per second

USER_RATES = {} # "Host@Address": <int>


_log_lock = threading.Lock()


def handle_client_rates():
    """
    Handle client rates
    Sholud be the only thing to access `USER_RATES`
    """


def log_packet(label: str, data: bytes):
    """
    Logging packet function
    """
    if len(data) <= MAX_PACKET_SIZE:
        return False

    try:
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        new_line = f"{current_time} [{label}] len={len(data)} data={data!r}\n"

        with _log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(new_line)
                print("Logged a packet!")
                return True
    except Exception as e:
        print("Failed to log packet :(")
        print(e)
        return True



def client_pipe(src, src_addr, dst, label):
    """
    Fucntion for client thread
    Keep the connection alive while safe data is being sent
    Close the connection if the client sends:
        ... a suspiciously large packet 
        ... too many packets
        ... a packet with a suspicious payload
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                # remote side closed
                break

            logged = log_packet(label, data)
            if logged:
                raise ValueError


            dst.sendall(data) # Forward packet

    except (ConnectionResetError, OSError, ValueError) as e:
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

def server_pipe(src, dst, label):
    """
    Fucntion for server thread
    Keep the connection alive while safe data is being sent
    If client send malicious data, close connection
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                # remote side closed
                break

            dst.sendall(data) # Forward packet to client

    except (ConnectionResetError, OSError, ValueError) as e:
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
    """
    Generic client handler
    """
    print(f"[proxy] New client from {client_addr}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((TARGET_HOST, TARGET_PORT))
    print(f"[proxy] Connected server to {TARGET_HOST}:{TARGET_PORT}")

    t1 = threading.Thread(
        target=client_pipe, args=(client_sock, client_addr, server_socket, "c->s"), daemon=True
    )
    t2 = threading.Thread(
        target=server_pipe, args=(server_socket, client_sock, "s->c"), daemon=True
    )
    t1.start()
    t2.start()


def main():
    """
    Main function
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen()
        print(
            f"[proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT} " \
            f"forwarding to {TARGET_HOST}:{TARGET_PORT}"
        )

        while True:
            client_sock, addr = s.accept()
            threading.Thread(
                target=handle_client, args=(client_sock, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
