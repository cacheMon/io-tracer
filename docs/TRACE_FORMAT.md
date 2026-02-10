# Trace Output Format Documentation

This document describes the CSV output format for all trace types produced by io-tracer-linux.

## Output Structure

The tracer creates a timestamped output directory containing subdirectories for each trace category:

```
output_YYYYMMDD_HHMMSS/
├── fs/                    # VFS (Virtual File System) traces
├── ds/                    # Block device traces
├── cache/                 # Page cache events
├── nw/                    # Network I/O traces
├── pagefault/             # Memory-mapped page fault events
├── iouring/               # io_uring async I/O events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

Each subdirectory contains CSV files that are automatically compressed to `.csv.gz` format.

---

## 1. VFS (Virtual File System) Traces

**Location:** `output_*/fs/fs_*.csv.gz`

**Description:** Captures all file system operations at the VFS layer, including reads, writes, opens, closes, and metadata operations.

### CSV Format

#### Standard Operations (Single Path)
```csv
timestamp,operation,pid,command,filename,size,inode,flags,latency_ns,offset,tid
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Event timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `operation` | string | Operation type (READ, WRITE, OPEN, CLOSE, etc.) |
| `pid` | integer | Process ID that performed the operation |
| `command` | string | Process command name (truncated to 16 chars) |
| `filename` | string | Full path of the file or "[decode_error]" if path unavailable |
| `size` | integer | Operation size in bytes (0 for metadata operations) |
| `inode` | integer | Inode number of the file |
| `flags` | string | Operation-specific flags (pipe-separated) |
| `latency_ns` | integer | Operation latency in nanoseconds (0 if not measured) |
| `offset` | integer | File offset for read/write operations (empty for others) |
| `tid` | integer | Thread ID for multi-threaded correlation (empty if not applicable) |

#### Dual-Path Operations (Rename, Link, Symlink)
```csv
timestamp,operation,pid,command,old_path->new_path,size,inode_old:inode_new,flags,latency_ns
```

| Column | Type | Description |
|--------|------|-------------|
| `old_path->new_path` | string | Source and destination paths separated by "->" |
| `inode_old:inode_new` | string | Source and destination inodes separated by ":" |

### Operations Captured

| Operation | Description | Size Field | Flags Field |
|-----------|-------------|------------|-------------|
| `READ` | File read via vfs_read | Bytes read | File flags (O_*) |
| `WRITE` | File write via vfs_write | Bytes written | File flags (O_*) |
| `OPEN` | File open via vfs_open | 0 | Open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.) |
| `CLOSE` | File close via __fput | 0 | File flags at close time |
| `FSYNC` | Data sync via vfs_fsync | 0 | File flags |
| `MMAP` | Memory map via do_mmap | Map size in bytes | Protection,Mapping flags |
| `MUNMAP` | Memory unmap via __vm_munmap | Unmap size in bytes | NO_FLAGS |
| `GETATTR` | Get file attributes | 0 | NO_FLAGS |
| `SETATTR` | Set file attributes | 0 | NO_FLAGS |
| `CHDIR` | Change directory | 0 | NO_FLAGS |
| `READDIR` | Directory listing | 0 | File flags |
| `UNLINK` | Delete file | 0 | NO_FLAGS |
| `TRUNCATE` | Truncate file | 0 | NO_FLAGS |
| `SYNC` | Global filesystem sync | 0 | NO_FLAGS |
| `RENAME` | Rename/move file | 0 | NO_FLAGS |
| `MKDIR` | Create directory | 0 | Mode (octal permissions) |
| `RMDIR` | Remove directory | 0 | NO_FLAGS |
| `LINK` | Create hard link | 0 | NO_FLAGS |
| `SYMLINK` | Create symbolic link | 0 | NO_FLAGS |
| `FALLOCATE` | Pre-allocate space | Allocated bytes | Fallocate mode flags |
| `SENDFILE` | Zero-copy file transfer | Transfer size | NO_FLAGS |
| `SPLICE` | Zero-copy pipe transfer | Transfer size | NO_FLAGS |
| `VMSPLICE` | Splice user pages to pipe | Transfer size | NO_FLAGS |
| `MSYNC` | Sync memory-mapped region | Region size | Sync flags (MS_ASYNC, MS_SYNC, MS_INVALIDATE) |
| `MADVISE` | Memory usage advice | Region size | Advice flags (MADV_DONTNEED, MADV_WILLNEED, etc.) |
| `DIO_READ` | Direct I/O read (bypasses page cache) | Bytes read | File flags |
| `DIO_WRITE` | Direct I/O write (bypasses page cache) | Bytes written | File flags |

### Flag Formats

**Open Flags** (O_* constants):
```
O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|O_NONBLOCK|
O_DSYNC|O_DIRECT|O_LARGEFILE|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC|
O_SYNC|O_PATH|O_TMPFILE
```

**MMAP Flags** (protection,mapping):
```
PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED|MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS|...
```

**Fallocate Mode**:
```
FALLOC_FL_KEEP_SIZE|FALLOC_FL_PUNCH_HOLE|FALLOC_FL_ZERO_RANGE|...
```

### Example Rows

```csv
2024-01-15 10:30:45.123456,WRITE,1234,python3,/home/user/data.txt,4096,789012,O_RDWR|O_CREAT,0,8192,1235
2024-01-15 10:30:45.234567,OPEN,1234,python3,/home/user/log.txt,0,789013,O_WRONLY|O_CREAT|O_APPEND,0,,1234
2024-01-15 10:30:45.345678,FSYNC,1234,python3,/home/user/data.txt,0,789012,O_RDWR|O_CREAT,0,,1234
2024-01-15 10:30:45.456789,RENAME,1234,mv,/tmp/old.txt->/tmp/new.txt,0,123456:123456,NO_FLAGS,0,,1234
2024-01-15 10:30:45.567890,SYMLINK,1234,ln,/usr/bin/python->/usr/bin/python3.10,0,0:654321,NO_FLAGS,0,,1234
2024-01-15 10:30:45.678901,READ,5678,cat,/etc/hosts,512,456789,O_RDONLY,50000,0,5678
2024-01-15 10:30:45.789012,MSYNC,1234,python3,/home/user/mmap.dat,4096,789014,MS_SYNC,120000,0,1235
2024-01-15 10:30:45.890123,DIO_WRITE,9999,postgres,/var/lib/postgres/data,8192,111222,O_DIRECT|O_SYNC,250000,16384,9999
```

---

## 2. Block Device Traces

**Location:** `output_*/ds/ds_*.csv.gz`

**Description:** Captures block layer I/O operations with latency measurements from issue to completion.

### CSV Format

```csv
timestamp,pid,command,sector,operation,size,latency_ms,tid,cpu_id,ppid,dev,queue_time_ms
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Completion timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `pid` | integer | Process ID (TGID) |
| `command` | string | Process command name |
| `sector` | integer | Starting LBA (Logical Block Address) |
| `operation` | string | I/O operation type (read, write, flush, discard, etc.) |
| `size` | integer | I/O size in bytes (nr_sectors × 512) |
| `latency_ms` | float | I/O latency in milliseconds (issue to completion) |
| `tid` | integer | Thread ID |
| `cpu_id` | integer | CPU core where completion occurred |
| `ppid` | integer | Parent process ID |
| `dev` | string | Device major:minor number (identifies partition) |
| `queue_time_ms` | float | Queue latency in milliseconds (insert to issue) |

### Operations

| Operation | Description |
|-----------|-------------|
| `read` | Block read operation (REQ_OP_READ) |
| `write` | Block write operation (REQ_OP_WRITE) |
| `flush` | Cache flush operation (REQ_OP_FLUSH) |
| `discard` | TRIM/DISCARD operation |
| `secure_erase` | Secure erase operation |
| `none` | No operation (metadata only) |

### Example Rows

```csv
2024-01-15 10:30:45.123456,1234,python3,2048000,write,8192,1.234,1235,0,1233,8:0,0.123
2024-01-15 10:30:45.234567,1234,python3,2048016,read,4096,0.567,1235,1,1233,8:0,0.045
2024-01-15 10:30:45.345678,1234,python3,0,flush,0,2.345,1235,2,1233,8:0,
```

---

## 3. Cache Events

**Location:** `output_*/cache/cache_*.csv.gz`

**Description:** Captures page cache operations including hits, misses, dirty pages, writeback, and evictions.

### CSV Format

```csv
timestamp,pid,command,event_type,inode,index,size,cpu_id,dev_id,count
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Event timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `pid` | integer | Process ID |
| `command` | string | Process command name |
| `event_type` | string | Cache event type (see below) |
| `inode` | integer | Inode number (0 if unavailable) |
| `index` | integer | Page cache index (page number) |
| `size` | integer | File size in pages (0 if unavailable) |
| `cpu_id` | integer | CPU core where event occurred |
| `dev_id` | integer | Device ID from superblock (0 if unavailable) |
| `count` | integer | Number of pages affected |

### Event Types

| Event Type | Description |
|------------|-------------|
| `HIT` | Page cache hit (page already in memory) |
| `MISS` | Page cache miss (page read from disk) |
| `DIRTY` | Page marked as dirty (modified) |
| `WRITEBACK_START` | Page writeback initiated |
| `WRITEBACK_END` | Page writeback completed |
| `EVICT` | Page evicted from cache |
| `INVALIDATE` | Cache invalidation requested |
| `DROP` | Explicit page drop |
| `READAHEAD` | Read-ahead (prefetch) operation |
| `RECLAIM` | Memory pressure reclaim |

### Example Rows

```csv
2024-01-15 10:30:45.123456,1234,python3,HIT,789012,100,256,0,2049,1
2024-01-15 10:30:45.234567,1234,python3,MISS,789012,101,256,1,2049,1
2024-01-15 10:30:45.345678,1234,python3,DIRTY,789012,100,256,0,2049,1
2024-01-15 10:30:45.456789,0,kworker,WRITEBACK_START,789012,100,256,2,2049,1
2024-01-15 10:30:45.567890,0,kworker,WRITEBACK_END,789012,100,256,2,2049,1
2024-01-15 10:30:45.678901,1234,python3,READAHEAD,789012,102,256,1,2049,8
2024-01-15 10:30:46.123456,0,kswapd0,RECLAIM,0,0,0,3,0,0
2024-01-15 10:30:46.234567,1234,python3,EVICT,789012,105,256,1,2049,1
2024-01-15 10:30:46.345678,5678,sh,DROP,789013,0,512,0,2049,1
```

**Note:** Cache events may be sampled. Check the tracer log for the current sampling rate (e.g., "Cache sampling enabled: 1:10" means 1 in 10 events are recorded).

---

## 4. Network Traces

**Location:** `output_*/nw/nw_*.csv.gz`

**Description:** Captures TCP and UDP network I/O operations with address and port information.

### CSV Format

```csv
timestamp,pid,command,source_addr,dest_addr,source_port,dest_port,size,direction
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Event timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `pid` | integer | Process ID |
| `command` | string | Process command name |
| `source_addr` | string | Source IP address (IPv4 or IPv6) |
| `dest_addr` | string | Destination IP address (IPv4 or IPv6) |
| `source_port` | integer | Source port number |
| `dest_port` | integer | Destination port number |
| `size` | integer | Bytes transferred |
| `direction` | string | "send" or "receive" |

### Protocols Captured

- **TCP:** tcp_sendmsg / tcp_recvmsg
- **UDP:** udp_sendmsg / udp_recvmsg

### Example Rows

```csv
2024-01-15 10:30:45.123456,1234,curl,192.168.1.100,93.184.216.34,54321,443,512,send
2024-01-15 10:30:45.234567,1234,curl,192.168.1.100,93.184.216.34,54321,443,1460,receive
2024-01-15 10:30:45.345678,5678,python3,::1,::1,8080,40123,256,send
2024-01-15 10:30:45.456789,5678,python3,::1,::1,8080,40123,128,receive
```

---

## 5. Page Fault Events

**Location:** `output_*/pagefault/pagefault_*.csv.gz`

**Description:** Captures file-backed page faults from memory-mapped I/O operations. Tracks which memory accesses trigger disk reads (major faults) vs cache hits (minor faults).

### CSV Format

```csv
timestamp,pid,tid,command,fault_type,severity,inode,offset,address,dev_id
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Event timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `pid` | integer | Process ID |
| `tid` | integer | Thread ID |
| `command` | string | Process command name |
| `fault_type` | string | Access type: "READ" or "WRITE" |
| `severity` | string | "MAJOR" (disk I/O) or "MINOR" (cache hit) |
| `inode` | integer | Backing file inode (0 for anonymous mappings) |
| `offset` | integer | File offset in pages (multiply by 4096 for bytes) |
| `address` | string | Faulting virtual address (hex) |
| `dev_id` | integer | Device ID from file's superblock (0 if unavailable) |

### Example Rows

```csv
2024-01-15 10:30:45.123456,1234,1235,python3,READ,MAJOR,789012,100,0x7f8a4c000000,2049
2024-01-15 10:30:45.234567,1234,1235,python3,READ,MINOR,789012,101,0x7f8a4c001000,2049
2024-01-15 10:30:45.345678,1234,1236,python3,WRITE,MAJOR,789012,102,0x7f8a4c002000,2049
2024-01-15 10:30:45.456789,5678,5678,app,READ,MINOR,456789,0,0x7f1234500000,2050
```

**Use Cases:**
- Analyze mmap I/O patterns and performance
- Identify major faults causing unexpected disk reads
- Correlate with cache events using inode numbers
- Detect memory pressure affecting file-backed pages

---

## 6. io_uring Events

**Location:** `output_*/iouring/iouring_*.csv.gz`

**Description:** Captures modern asynchronous I/O operations using the io_uring interface (Linux 5.1+). Tracks both file and network async operations.

### CSV Format

```csv
timestamp,pid,command,opcode,fd,offset,length,result,latency_ms
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Event timestamp (YYYY-MM-DD HH:MM:SS.ffffff) |
| `pid` | integer | Process ID |
| `command` | string | Process command name |
| `opcode` | string | io_uring operation type (see below) |
| `fd` | integer | File descriptor (0 if not applicable) |
| `offset` | integer | File offset for positioned I/O (empty if not applicable) |
| `length` | integer | Operation length/count (empty if not applicable) |
| `result` | integer | Operation result/return value (empty if not available) |
| `latency_ms` | float | Operation latency in milliseconds (empty if not measured) |

### Operation Types (Opcode)

| Opcode | Description |
|--------|-------------|
| `READ` | Asynchronous read |
| `WRITE` | Asynchronous write |
| `READV` | Vectored read |
| `WRITEV` | Vectored write |
| `READ_FIXED` | Read with pre-registered buffers |
| `WRITE_FIXED` | Write with pre-registered buffers |
| `FSYNC` | Asynchronous fsync |
| `SYNC_FILE_RANGE` | Sync specific file range |
| `FALLOCATE` | Asynchronous fallocate |
| `OPENAT` | Asynchronous file open |
| `CLOSE` | Asynchronous file close |
| `STATX` | Get extended file attributes |
| `SENDMSG` | Send message on socket |
| `RECVMSG` | Receive message from socket |
| `SEND` | Send data on socket |
| `RECV` | Receive data from socket |
| `ACCEPT` | Accept connection |
| `CONNECT` | Connect socket |
| `POLL_ADD` | Add poll request |
| `POLL_REMOVE` | Remove poll request |
| `TIMEOUT` | Set timeout |
| `MADVISE` | Memory advice |
| `FADVISE` | File access advice |
| `SPLICE` | Zero-copy data transfer |
| `IO_URING_ENTER` | The io_uring_enter syscall itself (batch submission) |
| `NOP` | No operation |

### Example Rows

```csv
2024-01-15 10:30:45.123456,1234,postgres,READ,5,0,8192,8192,0.234
2024-01-15 10:30:45.234567,1234,postgres,WRITE,5,8192,4096,4096,0.567
2024-01-15 10:30:45.345678,1234,postgres,FSYNC,5,,,0,1.234
2024-01-15 10:30:45.456789,5678,nginx,ACCEPT,10,,,15,0.012
2024-01-15 10:30:45.567890,5678,nginx,RECVMSG,15,,,1024,0.045
2024-01-15 10:30:45.678901,1234,app,IO_URING_ENTER,0,,32,,
```

**Use Cases:**
- Monitor high-performance async I/O applications
- Compare io_uring vs traditional I/O performance
- Analyze batched I/O submission patterns
- Track both file and network async operations
- Identify bottlenecks in async I/O pipelines

**Note:** The `IO_URING_ENTER` opcode represents the `io_uring_enter` syscall which can batch multiple operations. The `length` field for this operation indicates the number of operations submitted in that batch.

---

## 7. Process Snapshots

**Location:** `output_*/process/process_*.csv.gz`

**Description:** Periodic snapshots of all running processes (captured hourly by default).

### CSV Format

```csv
timestamp,pid,ppid,name,state,uid,gid,num_threads,cpu_percent,memory_percent,cmdline
```

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | datetime | Snapshot timestamp |
| `pid` | integer | Process ID |
| `ppid` | integer | Parent process ID |
| `name` | string | Process name |
| `state` | string | Process state (R=running, S=sleeping, D=disk sleep, Z=zombie, T=stopped) |
| `uid` | integer | User ID |
| `gid` | integer | Group ID |
| `num_threads` | integer | Number of threads |
| `cpu_percent` | float | CPU usage percentage |
| `memory_percent` | float | Memory usage percentage |
| `cmdline` | string | Full command line (space-separated) |

### Example Rows

```csv
2024-01-15 10:00:00.000000,1234,1,python3,S,1000,1000,4,2.5,1.2,python3 /home/user/script.py
2024-01-15 10:00:00.000000,5678,1,bash,S,1000,1000,1,0.0,0.1,/bin/bash
```

---

## 8. Filesystem Snapshots

**Location:** `output_*/filesystem_snapshot/filesystem_snapshot_*.csv.gz`

**Description:** Periodic directory tree snapshots showing file metadata (captured hourly by default).

### CSV Format

```csv
snapshot_timestamp,path,size,ctime,mtime,atime
```

| Column | Type | Description |
|--------|------|-------------|
| `snapshot_timestamp` | datetime | When the snapshot was taken (YYYY-MM-DD HH:MM:SS) |
| `path` | string | Full file/directory path (hashed if in anonymous mode) |
| `size` | integer | File size in bytes |
| `ctime` | datetime | File creation/metadata change time |
| `mtime` | datetime | File modification time |
| `atime` | datetime | File last access time |

### Example Rows

```csv
2024-01-15 10:00:00,/home/user/data.txt,1048576,2024-01-15 09:30:00,2024-01-15 09:45:00,2024-01-15 09:50:00
2024-01-15 10:00:00,/home/user/scripts/backup.sh,2048,2024-01-14 15:20:00,2024-01-15 08:10:00,2024-01-15 09:30:00
```

---

## 9. System Specification Files

**Location:** `output_*/system_spec/`

These are JSON files capturing system hardware and configuration at trace start:

- **cpu_info.json** - CPU model, cores, frequency
- **memory_info.json** - Total RAM, available memory
- **disk_info.json** - Storage devices and partitions
- **network_info.json** - Network interfaces and addresses
- **os_info.json** - Kernel version, distribution, hostname

---

## Data Types and Conventions

### Timestamps
- Format: `YYYY-MM-DD HH:MM:SS.ffffff` (microsecond precision)
- Timezone: Local system time
- Source: `datetime.datetime.today()` (Python) or `bpf_ktime_get_ns()` (eBPF)

### File Paths
- Always absolute paths when available
- Special values:
  - `[sendfile]` - sendfile() operation (no specific file)
  - `[decode_error]` - Path decoding failed
  - Empty string - Path unavailable (e.g., anonymous mmap)

### Process Information
- `pid` - Process ID (TGID in kernel terms)
- `tid` - Thread ID (kernel task PID)
- `ppid` - Parent Process ID
- `command` - Truncated to 16 characters (TASK_COMM_LEN)

### Sizes and Offsets
- All sizes in bytes unless specified
- Sector count: 512-byte sectors (multiply by 512 for bytes)
- Page size: 4096 bytes (4 KiB)
- Cache index × 4096 = byte offset

### Special Values
- `0` - Not applicable or unavailable
- Empty string - Field not captured for this event type
- `NO_FLAGS` - No flags set

---

## Compression and File Rotation

### Compression
- All CSV files are automatically compressed with gzip
- Original `.csv` files are deleted after compression
- Final archives: `.csv.gz` format

### File Rotation
Files are rotated and compressed when buffers reach thresholds:
- **VFS traces:** Every 1000 events
- **Block traces:** Every 1000 events  
- **Cache traces:** Every 10000 events (before sampling)
- **Network traces:** Every 1000 events
- **Snapshots:** Each snapshot creates a new file

File naming: `{type}_{YYYYMMDD_HHMMSS_mmm}.csv.gz`

---

## Reading Compressed Traces

### Command Line
```bash
# View compressed file
zcat output_*/fs/fs_*.csv.gz | less

# Parse with csvkit
zcat output_*/fs/fs_*.csv.gz | csvstat

# Count events
zcat output_*/fs/fs_*.csv.gz | wc -l

# Filter specific operation
zcat output_*/fs/fs_*.csv.gz | grep ",WRITE,"
```

### Python
```python
import gzip
import csv

with gzip.open('output_20240115_103045/fs/fs_20240115_103045_123.csv.gz', 'rt') as f:
    reader = csv.reader(f)
    for row in reader:
        timestamp, operation, pid, command, filename, size, inode, flags, latency = row
        print(f"{timestamp}: {operation} on {filename} by {command} ({pid})")
```

### Pandas
```python
import pandas as pd

# Single file
df = pd.read_csv('output_*/fs/fs_*.csv.gz', compression='gzip')

# Multiple files
import glob
files = glob.glob('output_*/fs/fs_*.csv.gz')
df = pd.concat([pd.read_csv(f, compression='gzip') for f in files])
```

---

## Performance Considerations

### Event Rates
Expected event rates (highly workload-dependent):
- **VFS:** 1-100K events/sec
- **Block:** 100-10K events/sec
- **Cache:** 10K-1M events/sec (before sampling)
- **Network:** 100-100K events/sec

### Sampling
Cache events support sampling to reduce overhead:
```bash
# Sample 1 in 10 cache events
python3 iotrc.py --cache-sample-rate 10
```

### Lost Events
If kernel buffers overflow, events may be lost. Monitor logs for:
```
[WARN] Lost N events in kernel buffer
```

Increase buffer size to reduce losses:
```bash
python3 iotrc.py --page-cnt 128  # Default: 64
```

---

## Version Information

This documentation applies to:
- **io-tracer-linux** version 1.0+
- **Kernel:** Linux 5.4+
- **BCC:** 0.18.0+

Field availability may vary by kernel version. Check logs for warnings about unavailable probes.
