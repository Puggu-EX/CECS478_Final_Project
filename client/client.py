import socket
import time
import random
import threading
import sys

PROXY_HOST = "proxy"
PROXY_PORT = 8000

# Flag to control message sending
send_message_flag = threading.Event()
send_malicious_flag = False  # Flag to send malicious message
send_test_flag = False  # Flag to send test message
send_custom_flag = False  # Flag to send custom message
custom_message = ""  # Store custom message
connection_closed = False
connection_lock = threading.Lock()

# Test packets to test the filter
TEST_PACKETS = [
    "Normal",  # Small normal packet
    "A" * 50,  # Exactly at the limit (50 bytes)
    "B" * 51,  # Just over the limit (51 bytes)
    "C" * 100,  # Large packet (100 bytes)
    "D" * 200,  # Very large packet (200 bytes)
    "Test with special chars: !@#$%^&*()",  # Special characters
    "Test\nwith\nnewlines",  # Newlines in message
    "",  # Empty message (just newline)
    "X" * 30 + "\x00" + "Y" * 20,  # Packet with null byte
]


def wait_for_input(sock):
    """
    Wait for user input (Enter key) to trigger message sending
    Works reliably in Docker containers
    """
    global connection_closed, send_malicious_flag, send_test_flag, send_custom_flag, custom_message

    # Wait a moment for the container to fully start and allow attachment
    time.sleep(2)

    print(
        "[client] Press ENTER to send a message, 'm' + ENTER for malicious message, 't' + ENTER for test packets, 'c' + ENTER for custom query, or 'q' + ENTER to quit",
        flush=True,
    )

    while True:
        with connection_lock:
            if connection_closed:
                break

        try:
            # Use input() which works reliably in Docker with stdin_open and tty
            user_input = input().strip()

            if user_input.lower() == "q":
                print("[client] Quitting...", flush=True)
                with connection_lock:
                    connection_closed = True
                break
            elif user_input.lower() == "m":
                # Set flag to send malicious message
                with connection_lock:
                    send_malicious_flag = True
                    send_test_flag = False
                send_message_flag.set()
            elif user_input.lower() == "t":
                # Set flag to send test message
                with connection_lock:
                    send_test_flag = True
                    send_malicious_flag = False
                    send_custom_flag = False
                send_message_flag.set()
            elif user_input.lower() == "c":
                # Prompt for custom message
                print("[client] Enter your custom message:", flush=True)
                try:
                    custom_input = input().strip()
                    with connection_lock:
                        custom_message = custom_input
                        send_custom_flag = True
                        send_malicious_flag = False
                        send_test_flag = False
                    send_message_flag.set()
                except (EOFError, OSError, KeyboardInterrupt):
                    print("[client] Failed to read custom message", flush=True)
                    continue
            else:
                # Any other input (including just Enter) sends a normal message
                with connection_lock:
                    send_malicious_flag = False
                    send_test_flag = False
                    send_custom_flag = False
                send_message_flag.set()

        except (EOFError, OSError, KeyboardInterrupt):
            # stdin not available or interrupted
            with connection_lock:
                connection_closed = True
            break
        except Exception:
            # Any other error, wait and retry
            time.sleep(0.1)
            continue


def main():
    global connection_closed, send_malicious_flag, send_test_flag, send_custom_flag, custom_message

    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_HOST, PROXY_PORT))
        print(f"[client] Connected to proxy at {PROXY_HOST}:{PROXY_PORT}", flush=True)

        # Start input listener thread
        input_thread = threading.Thread(target=wait_for_input, args=(s,), daemon=True)
        input_thread.start()

        while True:
            with connection_lock:
                if connection_closed:
                    break

            # Wait for input (or timeout to check connection status)
            if send_message_flag.wait(timeout=0.1):
                send_message_flag.clear()

                # Check what type of message should be sent
                with connection_lock:
                    send_malicious = send_malicious_flag
                    send_test = send_test_flag
                    send_custom = send_custom_flag
                    custom_msg = custom_message
                    send_malicious_flag = False  # Reset flag
                    send_test_flag = False  # Reset flag
                    send_custom_flag = False  # Reset flag

                if send_malicious:
                    # Send malicious message
                    malicious_msg = (
                        "This is a malicous message! You can tell by the odd size!"
                    )
                    message_to_send = malicious_msg
                elif send_test:
                    # Send a random test packet
                    message_to_send = random.choice(TEST_PACKETS)
                    print(f"[client] Sending test packet (size: {len(message_to_send)} bytes)", flush=True)
                elif send_custom:
                    # Send custom message
                    message_to_send = custom_msg
                    print(f"[client] Sending custom message (size: {len(message_to_send)} bytes)", flush=True)
                else:
                    # Generate random normal message
                    message_to_send = random.choice(
                        [
                            "Hello!",
                            "Safe!",
                            "No harm!",
                            "Hi!",
                        ]
                    )

                try:
                    s.sendall(f"{message_to_send}\n".encode())
                    print(f"[client] Sent: {message_to_send}", flush=True)
                except (OSError, BrokenPipeError):
                    print("[client] Connection closed while sending", flush=True)
                    break

            # Try to receive response (non-blocking check)
            s.settimeout(0.1)
            try:
                response = s.recv(4096)
                if not response:
                    print("[client] Connection closed by proxy/server", flush=True)
                    break
                decoded = response.decode().strip()
                print(f"[client] Got response: \n\t{decoded}", flush=True)
            except socket.timeout:
                # No data available, continue
                pass
            except (OSError, ConnectionResetError):
                print("[client] Connection closed", flush=True)
                break
            finally:
                s.settimeout(None)  # Reset to blocking mode

        with connection_lock:
            connection_closed = True


if __name__ == "__main__":
    main()
