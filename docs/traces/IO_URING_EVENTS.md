# io_uring Events

**Description:** Captures modern asynchronous I/O operations using io_uring (Linux 5.1+), which provides high-performance async I/O with minimal syscall overhead.

**Kernel Probes Attached:**
- `sys_enter_io_uring_enter` — io_uring submission/completion syscall (tracepoint)
- `__io_queue_sqe` — Individual I/O operation queueing (kprobe, if available)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | PID | `u32` | Process ID |
| 3 | Command | `string` | Process name (max 16 characters) |
| 4 | Opcode | `string` | io_uring operation type (see table below) |
| 5 | File Descriptor | `u32` | File descriptor for the operation; empty if `0` |
| 6 | Offset | `u64` | File offset for positioned I/O; empty if `0` |
| 7 | Length | `u32` | Number of operations (for `io_uring_enter`) or operation length; empty if `0` |
| 8 | Result | `s32` | Operation return value (bytes transferred or negative errno); empty if unavailable |
| 9 | Latency | `float` | Operation latency in milliseconds; empty if `0` |

## Operation Types (Opcodes)

| Code | Name | Category | Description |
|------|------|----------|-------------|
| 0 | `NOP` | Control | No operation (testing/padding) |
| 1 | `READV` | File I/O | Vectored read (scatter) |
| 2 | `WRITEV` | File I/O | Vectored write (gather) |
| 3 | `FSYNC` | File Ops | Flush file data to storage |
| 4 | `READ_FIXED` | File I/O | Read with pre-registered buffers |
| 5 | `WRITE_FIXED` | File I/O | Write with pre-registered buffers |
| 6 | `POLL_ADD` | Polling | Add poll request for fd |
| 7 | `POLL_REMOVE` | Polling | Remove poll request |
| 8 | `SYNC_FILE_RANGE` | File Ops | Sync a file data range |
| 9 | `SENDMSG` | Network | Send message on socket |
| 10 | `RECVMSG` | Network | Receive message from socket |
| 11 | `TIMEOUT` | Advanced | Set a timeout |
| 12 | `TIMEOUT_REMOVE` | Advanced | Remove a timeout |
| 13 | `ACCEPT` | Network | Accept incoming connection |
| 14 | `ASYNC_CANCEL` | Advanced | Cancel an in-progress async operation |
| 15 | `LINK_TIMEOUT` | Advanced | Linked timeout for chained requests |
| 16 | `CONNECT` | Network | Initiate outgoing connection |
| 17 | `FALLOCATE` | File Ops | Pre-allocate file space |
| 18 | `OPENAT` | File Management | Open a file |
| 19 | `CLOSE` | File Management | Close a file descriptor |
| 20 | `FILES_UPDATE` | Control | Update registered files |
| 21 | `STATX` | File Management | Get extended file attributes |
| 22 | `READ` | File I/O | Simple read |
| 23 | `WRITE` | File I/O | Simple write |
| 24 | `FADVISE` | File Ops | Provide file access advice to kernel |
| 25 | `MADVISE` | File Ops | Provide memory usage advice to kernel |
| 26 | `SEND` | Network | Send data on socket |
| 27 | `RECV` | Network | Receive data from socket |
| 28 | `OPENAT2` | File Management | Open file with extended flags |
| 29 | `EPOLL_CTL` | Polling | Epoll control from io_uring |
| 30 | `SPLICE` | Advanced | Splice data between file descriptors |
| 31 | `PROVIDE_BUFFERS` | Control | Provide buffers for buffer selection |
| 32 | `REMOVE_BUFFERS` | Control | Remove provided buffers |
| 255 | `IO_URING_ENTER` | Control | The `io_uring_enter` syscall itself (batched submission) |

**Output File:** `iouring/iouring_*.csv`

**Note:** io_uring support requires kernel 5.1+ and is automatically detected. The tracer captures the `io_uring_enter` syscall which batches multiple operations.
