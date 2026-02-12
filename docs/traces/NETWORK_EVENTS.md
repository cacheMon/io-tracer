# Network Events

**Description:** Captures network send and receive operations with connection details, protocol, latency, error codes, and message flags.

**Kernel Probes Attached:**
- `tcp_sendmsg` / `tcp_recvmsg` — TCP send/receive (kprobe + kretprobe for latency)
- `udp_sendmsg` / `udp_recvmsg` — UDP send/receive (kprobe + kretprobe for latency)
- `sys_enter_sendto` / `sys_enter_sendmsg` — Syscall MSG_* flag capture (tracepoint)
- `sys_enter_recvfrom` / `sys_enter_recvmsg` — Syscall MSG_* flag capture (tracepoint)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | PID | `u32` | Process ID |
| 3 | Command | `string` | Process name (max 16 characters) |
| 4 | Protocol | `string` | Transport protocol (see table below) |
| 5 | IP Version | `string` | IP version (`4` or `6`) |
| 6 | Source Address | `string` | Source IP address (IPv4 dotted or IPv6 colon notation) |
| 7 | Destination Address | `string` | Destination IP address |
| 8 | Source Port | `u16` | Source port number |
| 9 | Destination Port | `u16` | Destination port number |
| 10 | Size | `u32` | Payload size in bytes |
| 11 | Direction | `string` | I/O direction (see table below) |
| 12 | Latency | `u64` | Operation latency in nanoseconds (send operations); empty if `0` |
| 13 | Error | `string` | Error code name (see table below); empty on success |
| 14 | MSG Flags | `string` | Pipe-separated MSG_* flags (see table below); empty if none |

## Protocols

| Value | IPPROTO | Description |
|-------|---------|-------------|
| `TCP` | 6 | Transmission Control Protocol (reliable, ordered) |
| `UDP` | 17 | User Datagram Protocol (unreliable, unordered) |

## Directions

| Value | Description |
|-------|-------------|
| `send` | Outgoing data (sendmsg/sendto) |
| `receive` | Incoming data (recvmsg/recvfrom) |

## Error Codes

Displayed when the return value is negative (errno):

| Value | errno | Description |
|-------|-------|-------------|
| `EAGAIN` | 11 | Resource temporarily unavailable (non-blocking) |
| `EPIPE` | 32 | Broken pipe (remote closed) |
| `ECONNABORTED` | 103 | Connection aborted |
| `ECONNRESET` | 104 | Connection reset by peer |
| `ETIMEDOUT` | 110 | Connection timed out |
| `ECONNREFUSED` | 111 | Connection refused by remote |
| `EHOSTUNREACH` | 113 | No route to host |
| `EINPROGRESS` | 115 | Operation now in progress (non-blocking connect) |

## MSG Flags

Multiple flags can be combined with `|` (pipe):

| Flag | Hex | Description |
|------|-----|-------------|
| `MSG_OOB` | `0x01` | Send/receive out-of-band data |
| `MSG_PEEK` | `0x02` | Peek at incoming data without consuming |
| `MSG_DONTROUTE` | `0x04` | Send without routing table lookup |
| `MSG_DONTWAIT` | `0x20` | Non-blocking operation |
| `MSG_NOSIGNAL` | `0x40` | Do not generate SIGPIPE on broken pipe |
| `MSG_WAITALL` | `0x100` | Wait for full request or error |
| `MSG_MORE` | `0x4000` | More data coming (cork) |
| `MSG_ZEROCOPY` | `0x8000000` | Zero-copy send (kernel 4.14+) |

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/nw/nw_*.csv`
