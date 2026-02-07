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
- File path
- I/O size
- Inode number

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
- I/O size (in sectors/bytes)
- Latency (in milliseconds)
- Thread ID
- CPU ID
- Parent Process ID

**Output File:** `block_events.csv`

---

### 3. Page Cache Events

**Description:** Captures page cache operations including hits, misses, dirty pages, writebacks, evictions, and invalidations.

**Kernel Probes Attached (kernel version dependent):**
- **Cache Miss:** `filemap_add_folio` (5.14+) / `add_to_page_cache_lru` (older)
- **Cache Hit:** `folio_mark_accessed` (5.14+) / `mark_page_accessed` (older)
- **Dirty Page:** `__folio_mark_dirty` (5.14+) / `account_page_dirtied` (older)
- **Writeback Start:** `folio_clear_dirty_for_io` (5.14+) / `clear_page_dirty_for_io` (older)
- **Writeback End:** `folio_end_writeback` / `__folio_end_writeback` / `test_clear_page_writeback`
- **Eviction:** `filemap_remove_folio` / `__delete_from_page_cache`
- **Invalidation:** `invalidate_mapping_pages` / `truncate_inode_pages_range`

**Event Types:**
| ID | Event Type | Description |
|----|------------|-------------|
| 0 | HIT | Page was found in cache |
| 1 | MISS | Page was not in cache |
| 2 | DIRTY | Page marked as dirty |
| 3 | WRITEBACK_START | Page writeback initiated |
| 4 | WRITEBACK_END | Page writeback completed |
| 5 | EVICT | Page evicted from cache |
| 6 | INVALIDATE | Page invalidated |
| 7 | DROP | Page dropped from cache |

**Data Captured:**
- Timestamp
- Process ID and name
- Event type
- Inode number
- Page index

**Output File:** `cache_events.csv`

**Note:** Cache events can be sampled using `--cache-sample-rate N` to reduce overhead (captures 1 in N events).

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

## Snapshot Types

Snapshots are captured at trace start to provide system context and are not collected continuously.

### 1. Filesystem Snapshot

**Description:** Records the state of the filesystem at trace start, capturing file paths, sizes, and timestamps.

**Collection Method:**
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
- Iterates through all processes at 60-second intervals
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
│  │  Trace Types:    │    │ - _print_event_block (Block)      │  │
│  │  • VFS Events    │    │ - _print_event_cache (Cache)      │  │
│  │  • Block Events  │    │ - _print_event_net (Network)     │  │
│  │  • Cache Events  │    └─────────────────────────────────┘  │
│  │  • Net Events    │                                          │
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
