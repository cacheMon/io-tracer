# Network Drops & Retransmissions

**Description:** Captures TCP retransmission events and packet drops for network reliability analysis.

**Tracepoints Attached:**
- `tcp:tcp_retransmit_skb` — TCP segment retransmission (stable tracepoint, kernel 4.16+)
- `skb:kfree_skb` — Packet dropped by the kernel network stack

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Event Type | `string` | Drop/retransmit event type (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | Command | `string` | Process name (max 16 characters) |
| 5 | Protocol | `string` | Protocol name (`TCP` or `UDP`) |
| 6 | IP Version | `string` | IP version (`4` or `6`) |
| 7 | Source Address | `string` | Source IP address |
| 8 | Destination Address | `string` | Destination IP address |
| 9 | Source Port | `u16` | Source port number; empty if unavailable |
| 10 | Destination Port | `u16` | Destination port number; empty if unavailable |
| 11 | Packet Size | `u32` | Size of the packet/SKB in bytes; empty if unavailable |
| 12 | Drop Reason | `u32` | Kernel drop reason code; empty if not applicable |
| 13 | TCP State | `string` | TCP connection state at time of event (see table below); empty if not applicable |

## Event Types

| Value | Description |
|-------|-------------|
| `PACKET_DROP` | Packet dropped by the kernel network stack |
| `TCP_RETRANSMIT` | TCP segment retransmitted due to loss or timeout |

## TCP States

| Value | Description |
|-------|-------------|
| `ESTABLISHED` | Connection fully established, data transfer active |
| `SYN_SENT` | SYN sent, awaiting SYN-ACK (client connecting) |
| `SYN_RECV` | SYN received, SYN-ACK sent (server accepting) |
| `FIN_WAIT1` | FIN sent, awaiting ACK (active close initiated) |
| `FIN_WAIT2` | FIN acknowledged, awaiting FIN from peer |
| `TIME_WAIT` | Waiting for duplicate packets to expire after close |
| `CLOSE` | Socket fully closed |
| `CLOSE_WAIT` | FIN received, waiting for application to close |
| `LAST_ACK` | FIN sent after receiving FIN, awaiting final ACK |
| `LISTEN` | Socket is listening for incoming connections |
| `CLOSING` | Both sides sent FIN simultaneously |
| `NEW_SYN_RECV` | SYN received in new mini-socket (syncookie/fastopen) |

**Output File:** `nw_drop/nw_drop_*.csv`

**Note:** The `tcp:tcp_retransmit_skb` tracepoint is wrapped in try/except for kernel compatibility. On older kernels where it's unavailable, this category will be silently disabled.
