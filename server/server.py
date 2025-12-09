"""
Server file (Included to make my linter shut up)
"""
import socket
import os
import time

HOST = "0.0.0.0"
PORT = int(os.environ.get("SERVER_PORT", "9000"))


def packet_size_inspection(data) -> bool:
    """
    Checks if the packet size is too large; should have been denied
    """
    packet_size = len(data)
    if packet_size > 50:
        print("Packet should have been caught by proxy")
        print(f"\tLength [{packet_size}]")
        print(f"\tData Raw: {data}")
        print(f"\tData Decoded: {data.decode()}")
        return True
    return False


def handle_client(conn, addr):
    """
    Generic function to handle client connection
    """
    print(f"[server] Connection from {addr}", flush=True)
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                print("[server] Client closed connection", flush=True)
                break

            # Check if data is too large
            # packet_size_inspection(data)

            # Check if a specific client has sent too many packets; consider all clients
            # Check if user has sent too many packets


            text = data.decode().strip()
            print(f"[server] Received raw data: {text!r}", flush=True)

            response = f"[server] got {text}"

            print(f"[server] Sending response: {response!r}", flush=True)
            conn.sendall(response.encode())


def main():
    """
    Generic main function
    """
    print(f"[server] Listening on {HOST}:{PORT}", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            time.sleep(1)
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
