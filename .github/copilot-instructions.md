# Copilot Instructions for CECS478_Final_Project

## Project Overview

This is a **reverse proxy security demonstration** project showcasing how a middle-man proxy hardens web server security through IP obfuscation, host obfuscation, filtering, and logging. The architecture consists of three Python services orchestrated via Docker Compose.

## Architecture & Service Boundaries

**Three-tier containerized system:**

1. **Client** (`client/client.py`): Connects to proxy, sends test messages including normal and malicious payloads every 4 seconds after a 5-second startup delay
2. **Proxy** (`proxy/proxy.py`): Reverse proxy listening on port 8000, forwards to server on port 9000, implements packet logging and threat detection
3. **Server** (`server/server.py`): Backend service listening on port 9000, echoes received messages

**Data flow:** Client → Proxy (8000) → Server (9000)

**Key architectural pattern:** The proxy uses bidirectional threading with a `pipe()` function that maintains separate threads for client→server and server→client data streams, allowing simultaneous bidirectional communication while monitoring traffic.

## Critical Developer Workflows

### Building & Running
```bash
make up        # Docker build only
make demo      # Docker compose up (builds + runs)
make up && make demo  # Build then run
```

**Build process:** `docker-compose.yml` defines service order: server starts first, proxy depends on server, client depends on proxy. All use Python 3.12-slim base image.

### Debugging & Logs
- **Proxy logging:** Check `proxy/logs/log.txt` - logs packets from clients to server (c→s) when payload exceeds 50 bytes, enables threat detection
- **Console output:** Each service prints prefixed logs (`[server]`, `[proxy]`, `[client]`) - helpful for understanding real-time message flow
- **Volume mounts:** Proxy has read/write volume mount at `./proxy/logs:/logs` inside container

## Code Patterns & Conventions

**Network communication pattern (server/client):**
- Uses raw TCP sockets, not HTTP
- Messages are newline-separated text
- Data received in 4096-byte chunks, loop breaks on empty data (connection closed)

**Proxy filtering logic (`proxy.py`):**
- `log_packet(label, data)` function: Returns False for s→c traffic OR messages ≤50 bytes (benign), True triggers ValueError to close connection
- Thread-safe logging with `_log_lock` mutex
- Malicious payload detection: client intentionally sends "This is a malicous message! You can tell by the odd size!" (>50 bytes) to trigger proxy termination

**Environment configuration:**
- `server/server.py`: `SERVER_PORT` env var (default 9000)
- Proxy: Hardcoded to listen:8000, upstream:9000, target hostname "server" (Docker service name)
- Client: Hardcoded to connect to "proxy" hostname, port 8000

## Integration Points

**Docker Compose service discovery:** Services communicate using container names ("server", "proxy", "client") as hostnames - DNS resolution handled by Docker's internal network.

**Port mapping:**
- Proxy publicly exposes 8000 (where client connects)
- Server port 9000 only accessible from proxy
- Client doesn't expose ports

**State persistence:** Proxy logs to volume `./proxy/logs/log.txt` - survives container restarts.

## Project Specifics for Modifications

- **Adding security features:** Modify `pipe()` and `log_packet()` functions in `proxy.py`
- **Changing payload detection:** Edit the condition in `log_packet()` (currently `len(data) <= 50`)
- **Adding new message types:** Update client's random choice list in `client.py`, or modify server's echo response in `server.py`
- **Port configuration:** Update `docker-compose.yml` port bindings and corresponding HOST/PORT variables in Python files
