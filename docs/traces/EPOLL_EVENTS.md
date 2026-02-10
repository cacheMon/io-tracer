# Epoll/Multiplexing Events

**Description:** Captures I/O multiplexing operations for understanding event-driven architectures.

**Tracepoints Attached:**
- `syscalls:sys_enter_epoll_create1` / `sys_exit_epoll_create1` — Create epoll instance
- `syscalls:sys_enter_epoll_ctl` — Add/modify/remove FDs from epoll
- `syscalls:sys_enter_epoll_wait` / `sys_exit_epoll_wait` — Wait for events (with latency)
- `syscalls:sys_enter_poll` / `sys_exit_poll` — poll() syscall (with latency)
- `syscalls:sys_enter_select` / `sys_exit_select` — select() syscall (with latency)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Event Type | `string` | Multiplexing event type (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | TID | `u32` | Thread ID |
| 5 | Command | `string` | Process name (max 16 characters) |
| 6 | Epoll FD | `u32` | Epoll file descriptor; empty if not applicable |
| 7 | Target FD | `u32` | Target file descriptor being monitored; empty if not applicable |
| 8 | Operation | `string` | Epoll control operation (see table below); empty if not applicable |
| 9 | Event Mask | `string` | Pipe-separated epoll event flags (see table below); empty if not applicable |
| 10 | Max Events | `u32` | Maximum events to return (for EPOLL_WAIT); empty otherwise |
| 11 | Ready Count | `s32` | Number of ready file descriptors returned |
| 12 | Timeout | `u64` | Wait timeout in milliseconds; empty if not applicable |
| 13 | Latency | `u64` | Wait latency in nanoseconds (for EPOLL_WAIT/POLL/SELECT); empty otherwise |

## Event Types

| Value | Description |
|-------|-------------|
| `EPOLL_CREATE` | New epoll file descriptor created |
| `EPOLL_CTL` | File descriptor added/modified/removed from epoll |
| `EPOLL_WAIT` | Waiting for epoll events |
| `POLL` | `poll()` syscall invoked |
| `SELECT` | `select()` syscall invoked |

## Epoll Control Operations

| Value | Description |
|-------|-------------|
| `EPOLL_CTL_ADD` | Register a new file descriptor on the epoll instance |
| `EPOLL_CTL_DEL` | Remove a file descriptor from the epoll instance |
| `EPOLL_CTL_MOD` | Modify the event mask for a registered file descriptor |

## Epoll Event Flags

Multiple flags can be combined with `|` (pipe):

| Flag | Hex | Description |
|------|-----|-------------|
| `EPOLLIN` | `0x001` | File descriptor is ready for reading |
| `EPOLLPRI` | `0x002` | Urgent/out-of-band data available |
| `EPOLLOUT` | `0x004` | File descriptor is ready for writing |
| `EPOLLERR` | `0x008` | Error condition on the file descriptor |
| `EPOLLHUP` | `0x010` | Hang up on the file descriptor |
| `EPOLLNVAL` | `0x020` | Invalid file descriptor |
| `EPOLLRDNORM` | `0x040` | Normal data ready for reading |
| `EPOLLRDBAND` | `0x080` | Priority band data ready for reading |
| `EPOLLWRNORM` | `0x100` | Normal data ready for writing |
| `EPOLLWRBAND` | `0x200` | Priority band data ready for writing |
| `EPOLLMSG` | `0x400` | Message available (unused) |
| `EPOLLRDHUP` | `0x2000` | Peer closed connection or shut down writing half |
| `EPOLLEXCLUSIVE` | `1 << 28` | Exclusive wake-up mode |
| `EPOLLWAKEUP` | `1 << 29` | Prevent system suspend while event is being processed |
| `EPOLLONESHOT` | `1 << 30` | One-shot notification; must re-arm after event |
| `EPOLLET` | `1 << 31` | Edge-triggered notification mode |

**Output File:** `nw_epoll/nw_epoll_*.csv`
