# io_uring Events

**Description:** Captures io_uring asynchronous I/O operations including syscall entry, SQE submissions, completions with latency, and async worker executions.

**Kernel Probes Attached:**
- `__io_uring_enter` / `__sys_io_uring_enter` — io_uring_enter syscall
- `io_queue_sqe` / `io_submit_sqe` — SQE submission
- `io_req_complete_post` / `io_req_complete` — Completion
- `io_wq_submit_work` — Async worker execution

> **Note:** The `io_uring:io_uring_submit_sqe` and `io_uring:io_uring_complete` tracepoints are disabled by default due to incompatible struct field layouts across kernel versions. The kprobe-based implementations above provide cross-kernel compatibility.

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Timestamp NS | `u64` | Event timestamp in nanoseconds (boot time) |
| 3 | Event Type | `string` | Event type (see table below) |
| 4 | PID | `u32` | Process ID |
| 5 | TID | `u32` | Thread ID |
| 6 | Command | `string` | Process name (max 16 characters) |
| 7 | CPU | `u32` | CPU where event occurred |
| 8 | Ring FD | `u32` | io_uring file descriptor (ENTER events) |
| 9 | Ring Ptr | `hex` | io_ring_ctx pointer (for ring identification) |
| 10 | To Submit | `u32` | Number of SQEs to submit (ENTER events) |
| 11 | Min Complete | `u32` | Minimum completions to wait for (ENTER events) |
| 12 | Enter Flags | `string` | io_uring_enter flags (see table below) |
| 13 | Req Ptr | `hex` | io_kiocb request pointer (correlation key) |
| 14 | User Data | `u64` | User-provided data for correlation |
| 15 | Opcode | `string` | io_uring operation (see table below) |
| 16 | FD | `s32` | Target file descriptor |
| 17 | Length | `u32` | I/O length in bytes |
| 18 | Offset | `u64` | File offset |
| 19 | SQE Flags | `string` | SQE flags (see table below) |
| 20 | IO Prio | `u16` | I/O priority |
| 21 | Buf Index | `u16` | Buffer index (fixed buffers) |
| 22 | Personality | `u16` | Personality ID |
| 23 | Result | `s32` | Operation result (bytes or -errno) |
| 24 | Is Error | `u8` | 1 if result < 0, empty otherwise |
| 25 | Errno | `s32` | Errno value if error (positive) |
| 26 | Submit TS | `u64` | Submission timestamp (ns) |
| 27 | Complete TS | `u64` | Completion timestamp (ns) |
| 28 | Latency NS | `u64` | Completion latency in nanoseconds |
| 29 | Worker PID | `u32` | io-wq worker PID (WORKER events) |
| 30 | Worker TID | `u32` | io-wq worker TID (WORKER events) |
| 31 | Worker CPU | `u32` | io-wq worker CPU (WORKER events) |
| 32 | Is Async | `u8` | 1 if executed by io-wq worker |
| 33 | SQ Head | `u32` | Submission queue head (optional) |
| 34 | SQ Tail | `u32` | Submission queue tail (optional) |
| 35 | CQ Head | `u32` | Completion queue head (optional) |
| 36 | CQ Tail | `u32` | Completion queue tail (optional) |
| 37 | SQ Depth | `u32` | SQ backlog (sq_tail - sq_head) |
| 38 | CQ Depth | `u32` | CQ backlog (cq_tail - cq_head) |

## Event Types

| Value | Description |
|-------|-------------|
| `ENTER` | io_uring_enter() syscall - batch submission |
| `SUBMIT` | Individual SQE (Submission Queue Entry) queued |
| `COMPLETE` | Request completed with result |
| `WORKER` | Request executed by io-wq async worker |

## io_uring Opcodes

| Value | Opcode | Description |
|-------|--------|-------------|
| `NOP` | 0 | No operation |
| `READV` | 1 | Vectored read |
| `WRITEV` | 2 | Vectored write |
| `FSYNC` | 3 | File sync |
| `READ_FIXED` | 4 | Read with fixed buffer |
| `WRITE_FIXED` | 5 | Write with fixed buffer |
| `POLL_ADD` | 6 | Add poll monitor |
| `POLL_REMOVE` | 7 | Remove poll monitor |
| `SYNC_FILE_RANGE` | 8 | Sync file range |
| `SENDMSG` | 9 | Send message |
| `RECVMSG` | 10 | Receive message |
| `TIMEOUT` | 11 | Timeout operation |
| `TIMEOUT_REMOVE` | 12 | Remove timeout |
| `ACCEPT` | 13 | Accept connection |
| `ASYNC_CANCEL` | 14 | Cancel async operation |
| `LINK_TIMEOUT` | 15 | Linked timeout |
| `CONNECT` | 16 | Connect to socket |
| `FALLOCATE` | 17 | Allocate file space |
| `OPENAT` | 18 | Open file (relative) |
| `CLOSE` | 19 | Close file descriptor |
| `FILES_UPDATE` | 20 | Update registered files |
| `STATX` | 21 | Extended stat |
| `READ` | 22 | Read operation |
| `WRITE` | 23 | Write operation |
| `FADVISE` | 24 | File advice |
| `MADVISE` | 25 | Memory advice |
| `SEND` | 26 | Send data |
| `RECV` | 27 | Receive data |
| `OPENAT2` | 28 | Open file (extended) |
| `EPOLL_CTL` | 29 | Epoll control |
| `SPLICE` | 30 | Splice data |
| `PROVIDE_BUFFERS` | 31 | Provide buffers |
| `REMOVE_BUFFERS` | 32 | Remove buffers |
| `TEE` | 33 | Tee (splice copy) |
| `SHUTDOWN` | 34 | Socket shutdown |
| `RENAMEAT` | 35 | Rename file |
| `UNLINKAT` | 36 | Unlink file |
| `MKDIRAT` | 37 | Make directory |
| `SYMLINKAT` | 38 | Create symlink |
| `LINKAT` | 39 | Create hard link |

## io_uring_enter Flags (IORING_ENTER_*)

| Flag | Hex | Description |
|------|-----|-------------|
| `GETEVENTS` | `0x01` | Wait for completions |
| `SQ_WAKEUP` | `0x02` | Wake submission queue poller |
| `SQ_WAIT` | `0x04` | Wait for SQ space |
| `EXT_ARG` | `0x08` | Extended argument pointer |
| `REGISTERED_RING` | `0x10` | Use registered ring fd |

## SQE Flags (IOSQE_*)

| Flag | Hex | Description |
|------|-----|-------------|
| `FIXED_FILE` | `0x01` | Use fixed file table |
| `IO_DRAIN` | `0x02` | Issue after prior ops complete |
| `IO_LINK` | `0x04` | Link with next SQE |
| `IO_HARDLINK` | `0x08` | Hard link (continue on error) |
| `ASYNC` | `0x10` | Force async execution |
| `BUFFER_SELECT` | `0x20` | Select buffer from group |
| `CQE_SKIP_SUCCESS` | `0x40` | Skip CQE on success |

## Correlation

Events can be correlated using:

- **Primary key:** `Req Ptr` (io_kiocb pointer) - unique per request
- **Secondary key:** `User Data` - user-provided value from SQE

SUBMIT and COMPLETE events share the same `Req Ptr`, enabling latency calculation:
```
latency_ns = complete_ts_ns - submit_ts_ns
```

## Analysis Use Cases

This data enables:

- **Throughput analysis:** Requests per second by process/opcode
- **Latency distribution:** P50/P99 latency per operation type
- **Batch behavior:** Submission patterns via to_submit field
- **Async ratio:** WORKER events vs inline execution
- **Error tracking:** Error rates by operation type
- **Queue depth analysis:** SQ/CQ backlog monitoring
- **CPU migration:** Compare submission vs completion CPU

## Kernel Requirements

- **Minimum:** Linux 5.1 (io_uring introduction)
- **Recommended:** Linux 5.6+ (more stable symbols)
- **Tracepoint location:** `/sys/kernel/debug/tracing/events/io_uring/`

To verify io_uring symbol availability:
```bash
grep io_uring /proc/kallsyms | head -20
```

### Enabling Tracepoints (Advanced)

The io_uring tracepoint probes (`io_uring:io_uring_submit_sqe`, `io_uring:io_uring_complete`) are disabled by default because their struct field layouts vary across kernel versions. If your kernel's tracepoint format is compatible, you can enable them in `src/tracer/prober/prober.c`:

1. Check your kernel's tracepoint format:
   ```bash
   cat /sys/kernel/debug/tracing/events/io_uring/io_uring_submit_sqe/format
   ```

2. If the format includes `req`, `opcode`, `user_data`, and `flags` fields, change `#if 0` to `#if 1` around line 4218 in `prober.c`.

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/io_uring/io_uring_*.csv`
