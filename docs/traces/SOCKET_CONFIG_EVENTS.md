# Socket Configuration Events

**Description:** Captures socket option changes for performance-relevant settings.

**Tracepoints Attached:**
- `syscalls:sys_enter_setsockopt` — Set socket options
- `syscalls:sys_enter_getsockopt` — Get socket options

**Filtering:** Only `SOL_SOCKET` and `IPPROTO_TCP` level options are traced.

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Event Type | `string` | Operation type (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | Command | `string` | Process name (max 16 characters) |
| 5 | File Descriptor | `u32` | Socket file descriptor |
| 6 | Level | `string` | Socket option level (see table below) |
| 7 | Option Name | `string` | Socket option name (see table below) |
| 8 | Option Value | `s64` | Option value (interpretation depends on the option) |
| 9 | Return Value | `s32` | Syscall return value (`0` on success, negative errno on failure) |

## Event Types

| Value | Description |
|-------|-------------|
| `SET` | `setsockopt()` — setting a socket option |
| `GET` | `getsockopt()` — reading a socket option |

## Socket Option Levels

| Value | Description |
|-------|-------------|
| `SOL_SOCKET` | General socket-level options |
| `IPPROTO_TCP` | TCP protocol-level options |

## Socket Options

### SOL_SOCKET Level

| Value | Description |
|-------|-------------|
| `SO_REUSEADDR` | Allow address reuse (bind to address already in TIME_WAIT) |
| `SO_DONTROUTE` | Send without routing table lookup |
| `SO_BROADCAST` | Allow sending broadcast messages |
| `SO_SNDBUF` | Send buffer size in bytes |
| `SO_RCVBUF` | Receive buffer size in bytes |
| `SO_KEEPALIVE` | Enable TCP keepalive probes |
| `SO_LINGER` | Linger on close if data present (value = timeout seconds) |
| `SO_REUSEPORT` | Allow multiple sockets to bind to the same port |
| `SO_RCVTIMEO` | Receive timeout in microseconds |
| `SO_SNDTIMEO` | Send timeout in microseconds |

### IPPROTO_TCP Level

| Value | Description |
|-------|-------------|
| `TCP_NODELAY` | Disable Nagle's algorithm (1 = disable, 0 = enable) |
| `TCP_KEEPIDLE` | Idle time before first keepalive probe (seconds) |
| `TCP_KEEPINTVL` | Interval between keepalive probes (seconds) |
| `TCP_KEEPCNT` | Number of keepalive probes before declaring dead |
| `TCP_QUICKACK` | Enable quick ACKs (disable delayed ACK) |
| `TCP_DEFER_ACCEPT` | Defer accept until data arrives (seconds) |
| `TCP_CONGESTION` | Congestion control algorithm name |

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/nw_sockopt/nw_sockopt_*.csv`
