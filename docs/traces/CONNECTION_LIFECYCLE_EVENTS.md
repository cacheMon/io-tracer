# Connection Lifecycle Events

**Description:** Captures the full socket connection lifecycle from creation to shutdown.

**Tracepoints Attached:**
- `syscalls:sys_enter_socket` / `sys_exit_socket` — Socket creation
- `syscalls:sys_enter_bind` — Bind to address/port
- `syscalls:sys_enter_listen` — Start listening for connections
- `syscalls:sys_enter_accept4` / `sys_exit_accept4` — Accept incoming connections (with latency)
- `syscalls:sys_enter_connect` / `sys_exit_connect` — Initiate connection (with latency)
- `syscalls:sys_enter_shutdown` — Shutdown connection
- `syscalls:sys_enter_close` — Close file descriptor

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Event Type | `string` | Connection lifecycle event (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | TID | `u32` | Thread ID |
| 5 | Command | `string` | Process name (max 16 characters) |
| 6 | Domain | `string` | Socket address family (see table below) |
| 7 | Socket Type | `string` | Socket type (see table below) |
| 8 | Protocol | `string` | Protocol name (`TCP`, `UDP`) |
| 9 | IP Version | `string` | IP version (`4` or `6`) |
| 10 | Local Address | `string` | Local IP address; empty if not yet bound |
| 11 | Remote Address | `string` | Remote IP address; empty if not applicable |
| 12 | Local Port | `u16` | Local port number; empty if not yet bound |
| 13 | Remote Port | `u16` | Remote port number; empty if not applicable |
| 14 | File Descriptor | `u32` | Socket file descriptor; empty if unavailable |
| 15 | Backlog | `u32` | Listen backlog size (only for LISTEN events); empty otherwise |
| 16 | Latency | `u64` | Operation latency in nanoseconds (only for ACCEPT/CONNECT); empty otherwise |
| 17 | Return Value | `s32` | Syscall return value (`0` on success, negative errno on failure) |

## Event Types

| Value | Description |
|-------|-------------|
| `SOCKET_CREATE` | New socket file descriptor created |
| `BIND` | Socket bound to local address/port |
| `LISTEN` | Socket set to listening state |
| `ACCEPT` | New connection accepted from remote peer |
| `CONNECT` | Outgoing connection initiated to remote peer |
| `SHUTDOWN` | Connection shutdown initiated |
| `CLOSE` | Socket file descriptor closed |

## Socket Domains

| Value | Description |
|-------|-------------|
| `AF_UNIX` | Unix domain socket (local IPC) |
| `AF_INET` | IPv4 Internet protocols |
| `AF_INET6` | IPv6 Internet protocols |
| `AF_NETLINK` | Kernel/user-space communication |
| `AF_PACKET` | Low-level packet interface |

## Socket Types

| Value | Description |
|-------|-------------|
| `SOCK_STREAM` | Reliable, connection-oriented byte stream (TCP) |
| `SOCK_DGRAM` | Connectionless, unreliable datagrams (UDP) |
| `SOCK_RAW` | Raw network protocol access |
| `SOCK_SEQPACKET` | Reliable, connection-oriented, fixed-length datagrams |

## Shutdown Mode

The `SHUTDOWN` event uses the following `how` values:

| Value | Description |
|-------|-------------|
| `SHUT_RD` | Disallow further receives |
| `SHUT_WR` | Disallow further sends |
| `SHUT_RDWR` | Disallow further sends and receives |

## Important Notes

**CLOSE Event Filtering:**
- Only socket file descriptors are tracked for CLOSE events
- Regular files, pipes, and other non-socket fds do NOT trigger CLOSE events
- Tracking begins when a socket is created via `socket()` or accepted via `accept4()`
- This filtering prevents excessive noise from non-network file descriptor closes
- If you see unexpected CLOSE events, verify the fd was tracked as a socket from creation

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/nw_conn/nw_conn_*.csv`
