# VFS (Virtual File System) Events

**Description:** Captures file system operations at the VFS layer, intercepting all file access operations regardless of the underlying filesystem.

**Kernel Probes Attached:**
- `vfs_read` — File read operations
- `vfs_write` — File write operations
- `vfs_open` — File open operations
- `vfs_fsync` / `vfs_fsync_range` — File sync operations
- `vfs_unlink` — File deletion operations
- `vfs_getattr` — File attribute queries
- `do_mmap` / `__vm_munmap` — Memory-mapped file operations
- `iterate_dir` — Directory listing operations
- `do_truncate` — File truncation operations
- `vfs_rename` — File/directory rename operations
- `vfs_mkdir` — Directory creation operations
- `vfs_rmdir` — Directory removal operations
- `vfs_link` — Hard link creation operations
- `vfs_symlink` — Symbolic link creation operations
- `vfs_fallocate` — File space pre-allocation operations
- `do_sendfile` / `__do_sendfile` — Efficient file-to-file transfer operations

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | Operation | `string` | VFS operation type (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | Command | `string` | Process name (max 16 characters) |
| 5 | Filename | `string` | File path (or `old_path -> new_path` for dual-path operations) |
| 6 | Size | `u64` | I/O size in bytes (`0` for non-I/O operations) |
| 7 | Inode | `u64` | File inode number; empty if `0` |
| 8 | Flags | `string` | Operation-specific flags (see tables below); empty if none |
| 9 | Offset | `u64` | File offset for positioned I/O; empty if `0` |
| 10 | TID | `u32` | Thread ID for multi-threaded correlation; empty if `0` |

## Operation Types

| Code | Operation | Kernel Function | Dual-Path | Description |
|------|-----------|----------------|-----------|-------------|
| 1 | `READ` | `vfs_read()` | No | Read data from a file |
| 2 | `WRITE` | `vfs_write()` | No | Write data to a file |
| 3 | `OPEN` | `vfs_open()` | No | Open a file descriptor |
| 4 | `CLOSE` | `fput()` | No | Close/release a file descriptor |
| 5 | `FSYNC` | `vfs_fsync()` | No | Flush file data to storage |
| 6 | `MMAP` | `mmap_region()` | No | Memory-map a file |
| 7 | `MUNMAP` | `vm_munmap()` | No | Unmap a memory-mapped region |
| 8 | `GETATTR` | `vfs_getattr()` | No | Query file attributes (stat) |
| 9 | `SETATTR` | `vfs_setattr()` | No | Set file attributes (chmod, chown) |
| 10 | `CHDIR` | `sys_chdir()` | No | Change working directory |
| 11 | `READDIR` | `iterate_dir()` | No | Read directory entries |
| 12 | `UNLINK` | `vfs_unlink()` | No | Delete a file |
| 13 | `TRUNCATE` | `vfs_truncate()` | No | Truncate file to a given size |
| 14 | `SYNC` | `ksys_sync()` | No | System-wide filesystem sync |
| 15 | `RENAME` | `vfs_rename()` | Yes | Rename or move a file/directory |
| 16 | `MKDIR` | `vfs_mkdir()` | No | Create a directory |
| 17 | `RMDIR` | `vfs_rmdir()` | No | Remove an empty directory |
| 18 | `LINK` | `vfs_link()` | Yes | Create a hard link |
| 19 | `SYMLINK` | `vfs_symlink()` | No | Create a symbolic link |
| 20 | `FALLOCATE` | `vfs_fallocate()` | No | Pre-allocate file space |
| 21 | `SENDFILE` | `do_sendfile()` | No | Zero-copy file-to-socket transfer |
| 22 | `SPLICE` | `splice()` | No | Zero-copy pipe transfer |
| 23 | `VMSPLICE` | `vmsplice()` | No | Splice user pages to pipe |
| 24 | `MSYNC` | `msync()` | No | Sync memory-mapped region to disk |
| 25 | `MADVISE` | `madvise()` | No | Provide memory usage advice to kernel |
| 26 | `DIO_READ` | Direct I/O path | No | Direct I/O read (bypasses page cache) |
| 27 | `DIO_WRITE` | Direct I/O path | No | Direct I/O write (bypasses page cache) |

**Dual-Path Operations:** `RENAME` and `LINK` involve two paths. The filename column is formatted as `old_path -> new_path`.

## File Open Flags

Displayed for `OPEN` operations. Multiple flags are combined with `|` (pipe):

| Flag | Octal | Description |
|------|-------|-------------|
| `O_RDONLY` | `0o000` | Open for reading only |
| `O_WRONLY` | `0o001` | Open for writing only |
| `O_RDWR` | `0o002` | Open for reading and writing |
| `O_CREAT` | `0o100` | Create file if it does not exist |
| `O_EXCL` | `0o200` | Fail if file already exists (with O_CREAT) |
| `O_NOCTTY` | `0o400` | Do not assign controlling terminal |
| `O_TRUNC` | `0o1000` | Truncate file to zero length |
| `O_APPEND` | `0o2000` | Append writes to end of file |
| `O_NONBLOCK` | `0o4000` | Non-blocking I/O mode |
| `O_DSYNC` | `0o10000` | Synchronized data writes |
| `O_DIRECT` | `0o40000` | Direct I/O (bypass page cache) |
| `O_LARGEFILE` | `0o100000` | Allow large files (>2 GB on 32-bit) |
| `O_DIRECTORY` | `0o200000` | Fail if not a directory |
| `O_NOFOLLOW` | `0o400000` | Do not follow symbolic links |
| `O_NOATIME` | `0o1000000` | Do not update access time |
| `O_CLOEXEC` | `0o2000000` | Close file descriptor on exec |
| `O_SYNC` | `0o4010000` | Synchronized I/O (data + metadata) |
| `O_PATH` | `0o10000000` | Open for path operations only (no I/O) |
| `O_TMPFILE` | `0o20200000` | Create unnamed temporary file |

## Mmap Flags

Displayed for `MMAP` operations. Protection and mapping flags are comma-separated (`prot,map`), each internally pipe-separated:

### Protection Flags

| Flag | Hex | Description |
|------|-----|-------------|
| `PROT_NONE` | `0x0` | No access allowed |
| `PROT_READ` | `0x1` | Pages can be read |
| `PROT_WRITE` | `0x2` | Pages can be written |
| `PROT_EXEC` | `0x4` | Pages can be executed |

### Mapping Flags

| Flag | Hex | Description |
|------|-----|-------------|
| `MAP_SHARED` | `0x01` | Share mapping with other processes |
| `MAP_PRIVATE` | `0x02` | Create private copy-on-write mapping |
| `MAP_FIXED` | `0x10` | Place mapping at exact address |
| `MAP_ANONYMOUS` | `0x20` | Not backed by a file |
| `MAP_GROWSDOWN` | `0x0100` | Stack-like mapping that grows downward |
| `MAP_DENYWRITE` | `0x0800` | Deny write access to the file (ignored) |
| `MAP_EXECUTABLE` | `0x1000` | Mark mapping as executable (ignored) |
| `MAP_LOCKED` | `0x2000` | Lock pages in memory (no swap) |
| `MAP_NORESERVE` | `0x4000` | Do not reserve swap space |
| `MAP_POPULATE` | `0x8000` | Pre-fault pages into memory |
| `MAP_NONBLOCK` | `0x10000` | Do not block on I/O during populate |
| `MAP_STACK` | `0x20000` | Allocate at address suitable for stack |
| `MAP_HUGETLB` | `0x40000` | Use huge pages |

## Fallocate Flags

Displayed for `FALLOCATE` operations:

| Flag | Hex | Description |
|------|-----|-------------|
| `FALLOC_FL_KEEP_SIZE` | `0x01` | Allocate space without changing file size |
| `FALLOC_FL_PUNCH_HOLE` | `0x02` | Punch a hole (deallocate space) |
| `FALLOC_FL_COLLAPSE_RANGE` | `0x08` | Collapse a range (remove without leaving hole) |
| `FALLOC_FL_ZERO_RANGE` | `0x10` | Zero-fill a range |
| `FALLOC_FL_INSERT_RANGE` | `0x20` | Insert a range (shift data) |
| `FALLOC_FL_UNSHARE_RANGE` | `0x40` | Unshare shared extents (CoW) |

## Msync Flags

Displayed for `MSYNC` operations:

| Flag | Value | Description |
|------|-------|-------------|
| `MS_ASYNC` | 1 | Schedule writeback asynchronously |
| `MS_INVALIDATE` | 2 | Invalidate cached copies |
| `MS_SYNC` | 4 | Synchronous writeback (block until complete) |

## Madvise Behaviors

Displayed for `MADVISE` operations:

| Flag | Value | Description |
|------|-------|-------------|
| `MADV_NORMAL` | 0 | No special treatment (default) |
| `MADV_RANDOM` | 1 | Expect random access pattern |
| `MADV_SEQUENTIAL` | 2 | Expect sequential access pattern |
| `MADV_WILLNEED` | 3 | Will need these pages soon (trigger readahead) |
| `MADV_DONTNEED` | 4 | Do not need these pages (may be freed) |
| `MADV_FREE` | 8 | Pages can be freed when memory is needed |
| `MADV_REMOVE` | 9 | Remove pages and backing storage |
| `MADV_DONTFORK` | 10 | Do not inherit across fork |
| `MADV_DOFORK` | 11 | Inherit across fork (undo DONTFORK) |
| `MADV_MERGEABLE` | 12 | Enable KSM (Kernel Same-page Merging) |
| `MADV_UNMERGEABLE` | 13 | Disable KSM |
| `MADV_HUGEPAGE` | 14 | Enable Transparent Huge Pages |
| `MADV_NOHUGEPAGE` | 15 | Disable Transparent Huge Pages |
| `MADV_DONTDUMP` | 16 | Exclude from core dump |
| `MADV_DODUMP` | 17 | Include in core dump (undo DONTDUMP) |
| `MADV_WIPEONFORK` | 18 | Wipe pages on fork (security) |
| `MADV_KEEPONFORK` | 19 | Keep pages on fork (undo WIPEONFORK) |
| `MADV_COLD` | 20 | Hint that pages are cold (deactivate) |
| `MADV_PAGEOUT` | 21 | Hint to page out to swap |
| `MADV_POPULATE_READ` | 22 | Populate (fault in) pages for reading |
| `MADV_POPULATE_WRITE` | 23 | Populate (fault in) pages for writing |

## Empty Filenames

In some cases, the filename field may be empty. This occurs when the kernel data structures required for path resolution are unavailable or inaccessible. Common reasons include:

**1. Null or Invalid Dentry**
- The file's dentry (directory entry) structure is NULL or invalid
- Occurs during race conditions when files are being deleted or during unusual kernel states
- More common with short-lived temporary files or anonymous file descriptors

**2. Anonymous File Descriptors**
- Pipes and sockets (not backed by regular files)
- Anonymous memory mappings (`MAP_ANONYMOUS` without a backing file)
- memfd and other in-memory file descriptors
- File descriptors created via `O_TMPFILE` before being linked to the filesystem

**3. Early/Late Lifecycle Events**
- File descriptor operations during process creation or teardown
- Operations on file descriptors that are in the process of being closed
- Race conditions between file deletion and ongoing operations

**4. Virtual/Pseudo Filesystems**
- Some operations on procfs (`/proc`), sysfs (`/sys`), or other virtual filesystems
- These are filtered out by default, but edge cases may occur during the filtering check

**5. eBPF Probe Read Failures**
- Kernel memory read restrictions in hardened kernels
- Memory paging issues where the dentry name is swapped out
- Corruption or transient kernel data structure states

**6. Userspace Decode Failures**
- Unicode decode errors when the filename contains invalid UTF-8 sequences
- Non-standard character encodings in filenames
- Binary or corrupted data in the filename buffer

**Analysis Recommendations:**
- Empty filenames are typically safe to filter out for filesystem I/O analysis
- For network and IPC analysis, empty filenames are expected for sockets and pipes
- Check the inode field — if it's non-zero, the file exists but the path couldn't be resolved
- Correlate with the operation type and process command to determine if the empty filename is expected

**Output File:** `fs/fs_*.csv`
