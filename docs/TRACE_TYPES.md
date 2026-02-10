# Trace Types and Collection Methods

IO Tracer uses eBPF/BPF technology to intercept kernel functions and collect various types of I/O events. The tracer is composed of 4 real-time trace types and 3 snapshot types that provide system context.

## Real-Time Trace Types

### 1. VFS (Virtual File System) Events

**Description:** Captures file system operations at the VFS layer, intercepting all file access operations regardless of the underlying filesystem.

**Kernel Probes Attached:**
- `vfs_read` - File read operations
- `vfs_write` - File write operations
- `vfs_open` - File open operations
- `vfs_fsync` / `vfs_fsync_range` - File sync operations
- `vfs_unlink` - File deletion operations
- `vfs_getattr` - File attribute queries
- `do_mmap` / `__vm_munmap` - Memory-mapped file operations
- `iterate_dir` - Directory listing operations
- `do_truncate` - File truncation operations
- `vfs_rename` - File/directory rename operations
- `vfs_mkdir` - Directory creation operations
- `vfs_rmdir` - Directory removal operations
- `vfs_link` - Hard link creation operations
- `vfs_symlink` - Symbolic link creation operations
- `vfs_fallocate` - File space pre-allocation operations
- `do_sendfile` / `__do_sendfile` - Efficient file-to-file transfer operations

**Operation Types:**
| Operation | Description | Dual-Path |
|-----------|-------------|-----------|
| READ | File read operation | No |
| WRITE | File write operation | No |
| OPEN | File open operation | No |
| CLOSE | File close operation | No |
| FSYNC | File synchronization | No |
| MMAP | Memory-map a file | No |
| MUNMAP | Unmap memory-mapped file | No |
| GETATTR | Query file attributes | No |
| SETATTR | Set file attributes | No |
| CHDIR | Change directory | No |
| READDIR | Read directory entries | No |
| UNLINK | Delete a file | No |
| TRUNCATE | Truncate file | No |
| SYNC | System-wide sync | No |
| RENAME | Rename/move file or directory | Yes |
| MKDIR | Create directory | No |
| RMDIR | Remove directory | No |
| LINK | Create hard link | Yes |
| SYMLINK | Create symbolic link | No |
| FALLOCATE | Pre-allocate file space | No |
| SENDFILE | Zero-copy file transfer | No |
| SPLICE | Zero-copy pipe transfer | No |
| VMSPLICE | Splice user pages to pipe | No |
| MSYNC | Sync memory-mapped region | No |
| MADVISE | Memory usage advice to kernel | No |
| DIO_READ | Direct I/O read (bypasses page cache) | No |
| DIO_WRITE | Direct I/O write (bypasses page cache) | No |

**Dual-Path Operations:**
Some operations (RENAME, LINK) involve two paths (source and destination). These are formatted as: `old_path -> new_path` in the filename column.

**Flag Decoding:**
- **Open Flags:** O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_SYNC, O_DIRECT, etc.
- **Mmap Flags:** Protection (PROT_READ, PROT_WRITE, PROT_EXEC) and mapping (MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, etc.)
- **Fallocate Flags:** FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, etc.

**Data Captured:**
- Timestamp
- Operation type (read, write, open, close, etc.)
- Process ID (PID) and name
- Thread ID (TID) for multi-threaded correlation
- File path
- I/O size
- Inode number
- File offset (for read/write operations)
- Operation flags (O_RDONLY, O_SYNC, etc.)
- Operation latency in nanoseconds

**Output File:** `fs_events.csv`

---

### 2. Block I/O Events

**Description:** Captures block-level device I/O operations, providing insights into physical disk activity.

**Kernel Probes:** Attached via block layer instrumentation in the eBPF program.

**Data Captured:**
- Timestamp
- Process ID and name
- Sector location (LBA)
- Operation type (read, write, discard, etc.)
- I/O size (in bytes)
- Latency (in milliseconds) - time from issue to completion
- Queue latency (in milliseconds) - time from insert to issue
- Thread ID
- CPU ID
- Parent Process ID
- Device number (major:minor) - identifies the partition/device

**Output File:** `block_events.csv`

---

### 3. Page Cache Events

**Description:** Captures page cache operations including hits, misses, dirty pages, writebacks, evictions, invalidations, readahead, and memory reclaim. Enhanced with file context and size information for better analysis.

**Kernel Probes Attached (kernel version dependent):**
- **Cache Miss:** `filemap_add_folio` (5.14+) / `add_to_page_cache_lru` (older)
- **Cache Hit:** `folio_mark_accessed` (5.14+) / `mark_page_accessed` (older)
- **Dirty Page:** `__folio_mark_dirty` (5.14+) / `account_page_dirtied` (older)
- **Writeback Start:** `folio_clear_dirty_for_io` (5.14+) / `clear_page_dirty_for_io` (older)
- **Writeback End:** `folio_end_writeback` / `__folio_end_writeback` / `test_clear_page_writeback`
- **Eviction:** `filemap_remove_folio` / `__delete_from_page_cache`
- **Invalidation:** `invalidate_mapping_pages` / `truncate_inode_pages_range`
- **Readahead:** `__do_page_cache_readahead` / `page_cache_ra_order` (5.16+)
- **Reclaim:** `shrink_folio_list` (5.16+) / `shrink_page_list` (older)

**Event Types:**
| ID | Event Type | Description |
|----|------------|-------------|
| 0 | HIT | Page was found in cache |
| 1 | MISS | Page was not in cache, requires I/O |
| 2 | DIRTY | Page marked as dirty (modified) |
| 3 | WRITEBACK_START | Page writeback to disk initiated |
| 4 | WRITEBACK_END | Page writeback to disk completed |
| 5 | EVICT | Page evicted from cache (LRU) |
| 6 | INVALIDATE | Page invalidated (truncate/sync) |
| 7 | DROP | Page dropped from cache explicitly |
| 8 | READAHEAD | Pages prefetched into cache |
| 9 | RECLAIM | Pages reclaimed under memory pressure |

**Data Captured:**
- Timestamp (nanoseconds)
- Process ID and name (PID, comm)
- Event type (0-9)
- Inode number
- Page index (page offset within file)
- **Filename** (empty for cache events - see limitation below)
- **Size** (file size in pages, calculated from inode)
- **Offset** (byte offset in file, calculated as index * PAGE_SIZE)
- **Count** (number of pages affected by operation)

**Output File:** `cache/cache_*.csv`

**Format Example:**
```csv
2024-01-15 10:23:45.123456,1234,python,HIT,5678,42,,128,172032,1
2024-01-15 10:23:45.234567,1234,python,READAHEAD,5678,50,,128,204800,8
```

**Field Details:**
- **filename:** Empty for cache events (see limitation below)
- **size:** File size in pages (from inode->i_size >> 12)
- **offset:** Byte offset (index * 4096 on x86_64)
- **count:** Number of pages in operation (1 for single-page, N for bulk operations)

**Important Limitation - Filename Resolution:**
The filename field is **always empty** for cache events due to eBPF constraints:
- Cache events provide only: folio/page → address_space → inode
- Resolving inode → filename requires accessing inode->i_dentry
- inode->i_dentry is a list (hlist_head) of all hard links to the inode
- Iterating complex data structures in eBPF is not practical
- Use inode numbers to correlate with VFS events which do capture filenames
- Post-processing can map inode numbers to filenames from filesystem snapshots

**Note:** 
- Cache events can be sampled using `--cache-sample-rate N` to reduce overhead (captures 1 in N events).
- Tracepoint `mm_filemap_delete_from_page_cache` provides additional eviction coverage but lacks filename resolution.
- Readahead and reclaim events help identify prefetch behavior and memory pressure situations.

---

### 4. Network Events

**Description:** Captures network send and receive operations with connection details.

**Kernel Probes:** Attached via socket layer instrumentation in the eBPF program.

**Data Captured:**
- Timestamp
- Process ID and name
- Source IP address
- Destination IP address
- Source port
- Destination port
- Payload size (bytes)
- Direction (send/receive)

**Output File:** `network_events.csv`

---

### 5. Page Fault Events

**Description:** Captures file-backed page faults that occur when accessing memory-mapped files, providing insights into mmap I/O patterns.

**Kernel Probes Attached:**
- `filemap_fault` - File-backed page fault handler (via tracepoint)

**Data Captured:**
- Timestamp
- Process ID (PID) and name
- Thread ID (TID)
- Faulting virtual address
- Backing file inode number
- File offset (in pages)
- Fault type (READ or WRITE access)
- Fault severity (MAJOR = disk I/O required, MINOR = page already in cache)
- Device ID from file's superblock

**Output File:** `pagefault/pagefault_*.csv`

**Use Cases:**
- Analyze memory-mapped I/O patterns
- Identify major faults causing disk reads
- Correlate with VFS and cache events using inode numbers
- Track mmap-based file access by applications

---

### 6. io_uring Events

**Description:** Captures modern asynchronous I/O operations using io_uring (Linux 5.1+), which provides high-performance async I/O with minimal syscall overhead.

**Kernel Probes Attached:**
- `sys_enter_io_uring_enter` - io_uring submission/completion syscall (tracepoint)
- `__io_queue_sqe` - Individual I/O operation queueing (kprobe, if available)

**Operation Types Captured:**
Supports a wide range of io_uring operations including:
- **File I/O:** READ, WRITE, READV, WRITEV, READ_FIXED, WRITE_FIXED
- **File Ops:** FSYNC, SYNC_FILE_RANGE, FALLOCATE, FADVISE
- **File Management:** OPENAT, CLOSE, STATX
- **Network:** SENDMSG, RECVMSG, SEND, RECV, ACCEPT, CONNECT
- **Polling:** POLL_ADD, POLL_REMOVE
- **Advanced:** SPLICE, MADVISE, TIMEOUT, ASYNC_CANCEL

**Data Captured:**
- Timestamp
- Process ID (PID) and name
- Operation type/opcode (e.g., READ, WRITE, FSYNC)
- File descriptor
- File offset (for positioned I/O)
- Operation length/count
- Operation result (return value)
- Operation latency in milliseconds
- File inode (when available)

**Output File:** `iouring/iouring_*.csv`

**Use Cases:**
- Monitor modern async I/O workloads (databases, high-performance applications)
- Compare io_uring vs traditional I/O performance
- Analyze batched I/O submission patterns
- Track async network and file operations together

**Note:** io_uring support requires kernel 5.1+ and is automatically detected. The tracer captures the `io_uring_enter` syscall which batches multiple operations.

---

## Snapshot Types

Snapshots provide system context during tracing.

### 1. Filesystem Snapshot

**Description:** Records the state of the filesystem at trace start and periodically during the trace, capturing file paths, sizes, and timestamps.

**Collection Method:**
- First snapshot runs at trace start
- Subsequent snapshots are captured every hour (3600 seconds)
- Walks the filesystem hierarchy starting from `/`
- Records files up to configurable depth (default: 3)
- Skips files on different filesystems/devices
- Can operate in anonymous mode (hashes file paths)

**Data Captured:**
- File path (or hashed path)
- File size (bytes)
- Creation time
- Modification time

**Output File:** `filesystem_snap.csv.gz`

---

### 2. Process Snapshot

**Description:** Records information about all running processes periodically during the trace.

**Collection Method:**
- Iterates through all processes at 5-minute intervals
- Uses `psutil` for process information
- Background thread samples CPU utilization over multiple intervals

**Data Captured:**
- Timestamp
- Process ID (PID)
- Process name
- Command line (can be anonymized)
- Virtual memory size (KB)
- Resident set size (KB)
- Process creation time
- CPU utilization over 5s, 2m, and 1h intervals
- Process status

**Output File:** `process_snap.csv`

---

### 3. System Snapshot

**Description:** Captures hardware and software specifications for trace context.

**Collection Method:**
- Queries system information at trace start
- Uses `psutil`, `platform`, and subprocess calls
- Attempts IP geolocation for country detection

**Data Captured:**
- Operating system (name, release, version)
- CPU brand, cores, frequency
- GPU information (NVIDIA detection)
- Memory (total, available)
- Storage devices (model, size)
- Country code (from IP)

**Output File:** `device_spec.txt`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        IO Tracer                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │  eBPF Program   │  ◄── Kernel probes (kprobes/kretprobes)  │
│  │  (prober.c)     │                                           │
│  └────────┬────────┘                                           │
│           │ Perf buffer                                        │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  IOTracer.py     │───►│  Event Callbacks                 │  │
│  │                  │    │ - _print_event (VFS)              │  │
│  │  Trace Types:    │    │ - _print_event_dual (VFS dual)    │  │
│  │  • VFS Events    │    │ - _print_event_block (Block)      │  │
│  │  • Block Events  │    │ - _print_event_cache (Cache)      │  │
│  │  • Cache Events  │    │ - _print_event_net (Network)      │  │
│  │  • Net Events    │    │ - _print_event_pagefault (Fault)  │  │
│  │  • Page Faults   │    │ - _print_event_iouring (io_uring) │  │
│  │  • io_uring      │    └─────────────────────────────────┘  │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  Snapper Classes │    │  Snapshots                        │  │
│  │                  │    │ - FilesystemSnapper              │  │
│  │  Snapshots:      │    │ - ProcessSnapper                 │  │
│  │  • Filesystem    │    │ - SystemSnapper                  │  │
│  │  • Process       │    └─────────────────────────────────┘  │
│  │  • System        │                                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │  WriterManager  │    Output:                               │
│  │                  │    • fs_events.csv                      │  │
│  │                  │    • block_events.csv                   │  │
│  │                  │    • cache_events.csv                   │  │
│  │                  │    • network_events.csv                 │  │
│  │                  │    • pagefault_events.csv               │  │
│  │                  │    • iouring_events.csv                 │  │
│  │                  │    • filesystem_snap.csv.gz             │  │
│  │                  │    • process_snap.csv                   │  │
│  │                  │    • device_spec.txt                    │  │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Considerations

- **VFS tracing** has moderate overhead as it captures every file operation
- **Block tracing** is essential for understanding physical I/O patterns
- **Cache tracing** can generate high event rates; use sampling for long traces
- **Network tracing** captures connection metadata, not payload contents
- **Snapshots** are lightweight and only captured at trace start (except periodic process snapshots)
