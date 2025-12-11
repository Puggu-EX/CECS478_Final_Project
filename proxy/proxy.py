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
MAX_WARNINGS = 3

# Dictionary mapping client addresses to lists of timestamps
# Format: "host:port": [timestamp1, timestamp2, ...]
USER_RATES = {}
USER_WARNING = {}

_log_lock = threading.Lock()
_rate_lock = threading.Lock()

def shutdown(src, dst):
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


def check_rate_limit(client_addr: tuple) -> bool:
    """
    Check if client has exceeded rate limit.
    Returns True if rate limit is exceeded (should block), False otherwise.
    Uses a sliding window approach - tracks timestamps of messages in the last second.
    """
    current_time = time.time()
    addr_key = f"{client_addr[0]}:{client_addr[1]}"
    
    with _rate_lock:
        # Get or create the timestamp list for this client
        if addr_key not in USER_RATES:
            USER_RATES[addr_key] = []
        
        timestamps = USER_RATES[addr_key]
        
        # Remove timestamps older than 1 second (sliding window)
        timestamps[:] = [ts for ts in timestamps if current_time - ts < 1.0]
        
        # Check if rate limit exceeded
        if len(timestamps) >= MAX_RATE:
            return True  # Rate limit exceeded
        
        # Add current timestamp
        timestamps.append(current_time)
        return False  # Within rate limit


def cleanup_old_entries():
    """
    Periodically clean up old entries from USER_RATES dictionary.
    This runs in a background thread to prevent memory leaks.
    """
    while True:
        time.sleep(10)  # Run cleanup every 10 seconds
        current_time = time.time()
        with _rate_lock:
            # Remove entries that haven't been active in the last 60 seconds
            keys_to_remove = []
            for addr_key, timestamps in USER_RATES.items():
                # Remove old timestamps
                timestamps[:] = [ts for ts in timestamps if current_time - ts < 1.0]
                # If no recent activity, mark for removal
                if not timestamps or (timestamps and current_time - max(timestamps) > 60):
                    keys_to_remove.append(addr_key)
            for key in keys_to_remove:
                del USER_RATES[key]


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
        ... too many packets within a given time frame
        ... a packet with a suspicious payload
    """
    try:
        USER_WARNING[src_addr] = 0
        while True:
            data = src.recv(4096)
            if not data:
                # remote side closed
                break

            # Check rate limiting
            if check_rate_limit(src_addr):
                shutdown_client = False
                USER_WARNING[src_addr]+=1

                print(f"[proxy] Rate limit exceeded for {src_addr}")
                # Send rate limit message back to client instead of forwarding
                rate_limit_msg = f"[proxy] Warning! You are being rate limited: {USER_WARNING[src_addr]}\n"

                # Check if the user exceeded the number of warnings, if so shutdown
                if USER_WARNING[src_addr] > MAX_WARNINGS:
                    shutdown_client = True
                    rate_limit_msg = "[proxy] You exceeded the rate limit too many times\n"


                try:
                    src.sendall(rate_limit_msg.encode())
                    if shutdown_client:
                        shutdown(src, dst)
                except (OSError, BrokenPipeError):
                    print(f"[proxy] Failed to send rate limit message to {src_addr}")
                # Don't forward the packet, but keep connection alive
                continue

            logged = log_packet(label, data)
            if logged:
                print(f"[proxy] Malicious packet detected from {src_addr} (size: {len(data)})")
                # Send malicious message notification back to client instead of forwarding
                malicious_msg = "[proxy] A malicious message was sent, it was not delivered.\n"
                try:
                    src.sendall(malicious_msg.encode())
                except (OSError, BrokenPipeError):
                    print(f"[proxy] Failed to send malicious message notification to {src_addr}")
                # Don't forward the packet, but keep connection alive
                continue

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

    # Handles client to server communication
    t1 = threading.Thread(
        target=client_pipe, args=(client_sock, client_addr, server_socket, "c->s"), daemon=True
    )

    # Handles server to client communication
    t2 = threading.Thread(
        target=server_pipe, args=(server_socket, client_sock, "s->c"), daemon=True
    )

    t1.start()
    t2.start()


def main():
    """
    Main function
    """
    # Start background thread for cleaning up old rate limit entries
    cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
    cleanup_thread.start()
    
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
