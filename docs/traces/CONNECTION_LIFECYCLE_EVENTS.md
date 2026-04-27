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
| 7 | Socket Type | `string` | Socket type (see table below), triggered when SOCKET_CREATE |
| 8 | Protocol | `string` | Protocol name (`TCP`, `UDP`) |
| 9 | IP Version | `string` | IP version (`4` or `6`) |
| 10 | Local Address | `string` | Local IP address; empty if not yet bound |
| 11 | Remote Address | `string` | Remote IP address; empty if not applicable |
| 12 | Local Port | `u16` | Local port number; empty if not yet bound |
| 13 | Remote Port | `u16` | Remote port number; empty if not applicable |
| 14 | File Descriptor | `u32` | Socket file descriptor; empty if unavailable |
| 15 | Backlog | `u32` | Listen backlog size (only for LISTEN events); empty otherwise |
| 16 | ShutdownHow | `string` | Shutdown direction (only for SHUTDOWN events): `SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR`; empty otherwise |
| 17 | Latency | `u64` | Operation latency in nanoseconds (only for ACCEPT/CONNECT); empty otherwise |
| 18 | Return Value | `s32` | Syscall return value (`0` on success, negative errno on failure) |

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

## When Each Event Is Triggered

Each event fires **once per syscall invocation** — not per packet. Data flowing through an established connection (send/recv/read/write) generates **no rows** in this trace.

### `SOCKET_CREATE`
- **Probe:** `sys_exit_socket`
- Fires when `socket()` **returns successfully** with a valid file descriptor.
- Emitted at exit (not entry) so the assigned fd is available in `ret`.
- The fd is added to an internal tracking map so future `close()` calls on it can be detected.
- One row per `socket()` call regardless of whether the socket is ever used.

### `BIND`
- **Probe:** `sys_enter_bind`
- Fires when `bind()` is called, **before** the kernel processes it.
- Emitted at entry so the user-supplied `sockaddr` struct (address + port) is still readable from user memory.
- Captures local address and port that the socket is being bound to.

### `LISTEN`
- **Probe:** `sys_enter_listen`
- Fires when `listen()` is called, **before** the kernel processes it.
- Captures the `backlog` value (max pending connections queue length).
- One row per `listen()` call; re-calling `listen()` on the same fd emits another row.

### `ACCEPT`
- **Probe:** `sys_enter_accept4` (start timer) + `sys_exit_accept4` (emit row)
- Entry probe records a timestamp only — no row emitted.
- Exit probe fires when `accept4()` **returns**, meaning the kernel has dequeued an incoming connection and assigned it a new fd.
- `Latency` = time between entry and exit (i.e., how long the process blocked waiting for a client).
- The new client fd is added to the socket tracking map (same as `SOCKET_CREATE`).
- One row per accepted client connection.

### `CONNECT`
- **Probe:** `sys_enter_connect` (start timer) + `sys_exit_connect` (emit row)
- Entry probe records a timestamp only — no row emitted.
- Exit probe fires when `connect()` **returns**, meaning the TCP handshake completed (or failed).
- `Latency` = full round-trip time of the connection handshake (SYN → SYN-ACK → ACK).
- `Return Value` is `0` on success, `-EINPROGRESS` for non-blocking sockets still in progress, negative errno on failure.
- One row per `connect()` call.

### `SHUTDOWN`
- **Probe:** `sys_enter_shutdown`
- Fires when `shutdown()` is called, **before** the kernel processes it.
- Captures the `how` flag in the `ShutdownHow` column: `SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR`.
- Does not mean the connection is fully closed — the fd still exists until `close()` is called.

### `CLOSE`
- **Probe:** `sys_enter_close`
- Fires when `close()` is called on an fd **only if that fd was previously tracked as a socket** (created via `socket()` or `accept4()`).
- Regular file, pipe, and other non-socket fds are silently skipped — no row emitted.
- One row per socket close, regardless of whether `shutdown()` was called first.

### What Is NOT Captured
- **Data transfer:** `send()`, `recv()`, `read()`, `write()`, `sendmsg()`, `recvmsg()` — no rows emitted per packet or per byte.
- **Kernel-internal events:** TCP retransmits, RST packets, TIME_WAIT transitions.
- **`accept()` (without the `4`):** Only `accept4()` is traced; processes using the older `accept()` syscall will not appear.

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
