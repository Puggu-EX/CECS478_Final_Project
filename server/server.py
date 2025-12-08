import socket

HOST = "0.0.0.0"
PORT = 9000


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[server] Connection from {addr}")
                data = conn.recv(4096)
                if not data:
                    print("[server] didnt get anything back")
                    continue
                response = b"server echo: " + data
                conn.sendall(response)
                print(f"[server] Responded and closed connection")


if __name__ == "__main__":
    main()
