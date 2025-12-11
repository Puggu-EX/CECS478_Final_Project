import socket
import threading
import time
import re

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
    Periodically clean up old entries from USER_RATES and USER_WARNING dictionaries.
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
                if key in USER_RATES:
                    del USER_RATES[key]
                # Also clean up warnings for inactive clients
                if key in USER_WARNING:
                    del USER_WARNING[key]


def detect_http_request(data: bytes) -> bool:
    """
    Detect if packet contains an HTTP request.
    Looks for HTTP methods followed by paths/versions, or HTTP headers.
    More strict to avoid false positives on normal text.
    """
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        text_upper = text.upper()
        lines = text.split('\n')
        first_line = lines[0].strip() if lines else ""
        first_line_upper = first_line.upper()
        
        # HTTP methods that must be followed by a path or HTTP version
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']
        
        # Check for HTTP methods at the start, but require they're followed by a path or HTTP version
        for method in http_methods:
            if first_line_upper.startswith(method + ' '):
                # Method found - check if followed by valid HTTP request pattern
                # Should have: METHOD /path HTTP/version OR METHOD http://host/path
                remaining = first_line[len(method):].strip()
                
                # Check for HTTP version (strong indicator)
                if 'HTTP/1.' in remaining.upper() or 'HTTP/2' in remaining.upper():
                    return True
                
                # Check for URL pattern (http:// or https://)
                if remaining.upper().startswith('HTTP://') or remaining.upper().startswith('HTTPS://'):
                    return True
                
                # Check for path starting with / (common HTTP request pattern)
                if remaining.startswith('/'):
                    return True
                
                # If method is followed by something that looks like a path/URL, it's likely HTTP
                # But be more strict - require at least HTTP version or multiple headers
                # Don't flag just "GET something" as it could be normal text
        
        # Check for HTTP version indicator (must be with a method or in proper context)
        if 'HTTP/1.' in text_upper or 'HTTP/2' in text_upper:
            # If HTTP version is present, check if it's in a request line context
            # Look for pattern like "GET /path HTTP/1.1" or "POST /path HTTP/2"
            import re
            http_version_pattern = r'HTTP/[12]\.?\d?'
            if re.search(http_version_pattern, text_upper):
                # Check if there's a method before it
                for method in http_methods:
                    method_pos = text_upper.find(method + ' ')
                    http_pos = text_upper.find('HTTP/')
                    if method_pos != -1 and http_pos != -1 and method_pos < http_pos:
                        return True
        
        # Check for multiple HTTP headers (stronger indicator than single header)
        http_headers = [
            'HOST:', 'USER-AGENT:', 'CONTENT-TYPE:', 'CONTENT-LENGTH:',
            'ACCEPT:', 'AUTHORIZATION:', 'COOKIE:', 'REFERER:',
            'ORIGIN:', 'X-REQUESTED-WITH:', 'ACCEPT-LANGUAGE:',
            'CONNECTION:', 'CACHE-CONTROL:', 'ACCEPT-ENCODING:'
        ]
        
        header_count = 0
        for line in lines:
            line_upper = line.strip().upper()
            for header in http_headers:
                # Header must be at start of line (with optional whitespace)
                if line_upper.startswith(header) or line_upper.startswith(header.replace(':', '')):
                    header_count += 1
                    break
        
        # Multiple headers strongly suggest HTTP request
        if header_count >= 2:
            return True
        
        # Single header + method is also a strong indicator
        if header_count >= 1:
            for method in http_methods:
                if method + ' ' in first_line_upper:
                    return True
        
        return False
    except:
        return False


def detect_code(data: bytes) -> bool:
    """
    Detect if packet contains code patterns.
    Looks for code keywords and syntax patterns, but avoids false positives on normal text.
    """
    try:
        text = data.decode('utf-8', errors='ignore')
        
        # Code keywords that are less likely to appear in normal text
        code_keywords = [
            'function(', 'function ', 'def ', 'class ', 'import ', 'from ',
            'var ', 'let ', 'const ', 'return ', 'async ', 'await ',
            'public ', 'private ', 'protected ', 'static ', 'void ',
            'int ', 'string ', 'boolean ', 'float ', 'double ',
            '<?php', '<?=', '<?', '#!/', '#include', '#define',
            'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'FROM ',
            'console.log', 'print(', 'System.out', 'printf(',
        ]
        
        text_lower = text.lower()
        keyword_count = 0
        
        for keyword in code_keywords:
            if keyword.lower() in text_lower:
                keyword_count += 1
        
        # Multiple code keywords suggest actual code
        if keyword_count >= 2:
            return True
        
        # Check for code-like patterns
        # Multiple semicolons (common in code)
        if text.count(';') >= 2:
            return True
        
        # Multiple curly braces (common in code)
        if (text.count('{') >= 2 or text.count('}') >= 2) and keyword_count >= 1:
            return True
        
        # Multiple brackets with code-like structure
        if (text.count('[') >= 2 and text.count(']') >= 2) and keyword_count >= 1:
            return True
        
        # Assignment operators common in code
        assignment_ops = [' = ', ' += ', ' -= ', ' *= ', ' /= ', ' := ']
        assignment_count = sum(1 for op in assignment_ops if op in text)
        if assignment_count >= 2:
            return True
        
        # Function call patterns: word followed by (
        import re
        function_pattern = r'\b\w+\s*\('
        function_calls = len(re.findall(function_pattern, text))
        if function_calls >= 3:  # Multiple function calls suggest code
            return True
        
        return False
    except:
        return False


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



def increment_warning(addr_key: str) -> int:
    """
    Increment warning count for a client and return the new count.
    Thread-safe.
    """
    with _rate_lock:
        if addr_key not in USER_WARNING:
            USER_WARNING[addr_key] = 0
        USER_WARNING[addr_key] += 1
        return USER_WARNING[addr_key]


def get_warning_count(addr_key: str) -> int:
    """
    Get current warning count for a client.
    Thread-safe.
    """
    with _rate_lock:
        return USER_WARNING.get(addr_key, 0)


def client_pipe(src, src_addr, dst, label):
    """
    Fucntion for client thread
    Keep the connection alive while safe data is being sent
    Close the connection if the client sends:
        ... a suspiciously large packet 
        ... too many packets within a given time frame
        ... a packet with a suspicious payload
    """
    addr_key = f"{src_addr[0]}:{src_addr[1]}"
    
    try:
        # Initialize warning count for this client
        with _rate_lock:
            if addr_key not in USER_WARNING:
                USER_WARNING[addr_key] = 0
        
        while True:
            data = src.recv(4096)
            if not data:
                # remote side closed
                break

            shutdown_client = False

            # Check rate limiting
            if check_rate_limit(src_addr):
                warning_count = increment_warning(addr_key)

                print(f"[proxy] Rate limit exceeded for {src_addr} (Warning: {warning_count})")
                # Send rate limit message back to client instead of forwarding
                rate_limit_msg = f"[proxy] Warning! You are being rate limited: {warning_count}/{MAX_WARNINGS}\n"

                # Check if the user exceeded the number of warnings, if so shutdown
                if warning_count > MAX_WARNINGS:
                    shutdown_client = True
                    rate_limit_msg = "[proxy] You exceeded the warning limit too many times. Connection closed.\n"

                try:
                    src.sendall(rate_limit_msg.encode())
                    if shutdown_client:
                        shutdown(src, dst)
                        break
                except (OSError, BrokenPipeError):
                    print(f"[proxy] Failed to send rate limit message to {src_addr}")
                # Don't forward the packet, but keep connection alive
                continue

            # Check for code or HTTP requests
            is_http = detect_http_request(data)
            is_code = detect_code(data)
            
            if is_http or is_code:
                warning_count = increment_warning(addr_key)
                
                violation_type = "HTTP request" if is_http else "code"
                print(f"[proxy] {violation_type} detected from {src_addr} (Warning: {warning_count})")
                # Send violation message back to client instead of forwarding
                violation_msg = f"[proxy] Warning! {violation_type.capitalize()} detected, it was not delivered: {warning_count}/{MAX_WARNINGS}\n"
                
                # Check if the user exceeded the number of warnings, if so shutdown
                if warning_count > MAX_WARNINGS:
                    shutdown_client = True
                    violation_msg = "[proxy] You exceeded the warning limit too many times. Connection closed.\n"
                
                try:
                    src.sendall(violation_msg.encode())
                    if shutdown_client:
                        shutdown(src, dst)
                        break
                except (OSError, BrokenPipeError):
                    print(f"[proxy] Failed to send {violation_type} violation message to {src_addr}")
                # Don't forward the packet, but keep connection alive
                continue

            logged = log_packet(label, data)
            if logged:
                warning_count = increment_warning(addr_key)
                
                print(f"[proxy] Malicious packet detected from {src_addr} (size: {len(data)}, Warning: {warning_count})")
                # Send malicious message notification back to client instead of forwarding
                malicious_msg = f"[proxy] Warning! A malicious message was sent, it was not delivered: {warning_count}/{MAX_WARNINGS}\n"
                
                # Check if the user exceeded the number of warnings, if so shutdown
                if warning_count > MAX_WARNINGS:
                    shutdown_client = True
                    malicious_msg = "[proxy] You exceeded the warning limit too many times. Connection closed.\n"
                
                try:
                    src.sendall(malicious_msg.encode())
                    if shutdown_client:
                        shutdown(src, dst)
                        break
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
