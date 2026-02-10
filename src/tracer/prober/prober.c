/**
 * @file prober.c
 * @brief eBPF-based I/O Tracer for comprehensive system I/O monitoring
 *
 * This BPF program implements a multi-layer I/O tracing system that monitors:
 * - VFS (Virtual File System) operations: read, write, open, close, fsync, etc.
 * - Block layer events: request queuing, issue, and completion with latency
 * - Page cache operations: hits, misses, dirty pages, writeback, eviction
 * - Network I/O: TCP/UDP send and receive operations
 * - Memory-mapped I/O: page faults, msync, madvise
 * - Async I/O: io_uring operations, direct I/O, splice
 *
 * The tracer uses BCC (BPF Compiler Collection) and attaches to kernel
 * functions via kprobes, kretprobes, and tracepoints.
 *
 * @note Requires CAP_SYS_ADMIN or CAP_BPF capability to load
 * @note Kernel version compatibility macros handle API differences
 */

#define BPF_NO_KFUNC_PROTO
#include <linux/ptrace.h>

/* Kernel version compatibility: BPF kfunc declarations were restructured
 * in kernel 6.14+, requiring empty struct placeholders */
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,14,0)
// #define BPF_NO_KFUNC_PROTO
// struct bpf_wq {};
// #endif

/* ============================================================================
 * KERNEL VERSION COMPATIBILITY
 * ============================================================================
 * These macros and struct placeholders ensure compatibility across different
 * kernel versions by providing missing definitions.
 */

/* bpf_timer struct was introduced in kernel 5.17 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
struct bpf_timer {};
#endif

/* BPF atomic load/store instructions - fallback definitions */
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 0xe1  /**< Atomic load with acquire semantics */
#endif

#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0xe2  /**< Atomic store with release semantics */
#endif

#ifndef BPF_PSEUDO_FUNC
#define BPF_PSEUDO_FUNC 4  /**< Pseudo function for BPF-to-BPF calls */
#endif

#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ULL << 3)  /**< Broadcast flag for BPF maps */
#endif

/* bpf_task_work struct introduced in kernel 6.14 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
struct bpf_task_work {};
#endif

/* ============================================================================
 * KERNEL HEADERS
 * ============================================================================
 * Required kernel headers for accessing kernel data structures and functions.
 */

#include <bcc/proto.h>        /* BCC protocol helpers for network tracing */
#include <linux/blk_types.h>  /* Block layer types (bio, request) */
#include <linux/blkdev.h>     /* Block device structures */
#include <linux/dcache.h>     /* Dentry cache structures for path resolution */
#include <linux/fs.h>         /* VFS structures (file, inode, super_block) */
#include <linux/fs_struct.h>  /* Process filesystem context (pwd, root) */
#include <linux/in.h>         /* IPv4 socket address structures */
#include <linux/in6.h>        /* IPv6 socket address structures */
#include <linux/mm.h>         /* Memory management (page, vm_area_struct) */
#include <linux/sched.h>      /* Process/task structures */
#include <linux/stat.h>       /* File mode/permission macros (S_ISREG, etc.) */
#include <linux/tcp.h>        /* TCP protocol structures */
#include <linux/udp.h>        /* UDP protocol structures */
#include <net/inet_sock.h>    /* Internet socket structures */
#include <net/sock.h>         /* Generic socket structures */

/* Block multi-queue header - only available in kernel 5.16+ */
#ifdef __has_include
#if __has_include(<linux/blk-mq.h>)
#include <linux/blk-mq.h>  /* Block layer multi-queue structures */
#endif
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#include <linux/blk-mq.h>
#endif
#endif

/* ============================================================================
 * CONSTANTS AND CONFIGURATION
 * ============================================================================
 */

/** Maximum length for captured filenames (including null terminator) */
#define FILENAME_MAX_LEN 256

/** Length of block operation type string (e.g., "R", "W", "RA") */
#define OP_LEN 8

/* ============================================================================
 * FILESYSTEM MAGIC NUMBERS
 * ============================================================================
 * These magic numbers identify virtual/pseudo filesystems that should be
 * excluded from I/O tracing to reduce noise and focus on real storage I/O.
 * Each filesystem has a unique magic number in its superblock.
 */

#define PROC_SUPER_MAGIC 0x9fa0           /**< /proc filesystem */
#define SYSFS_MAGIC 0x62656572             /**< /sys filesystem */
#define TMPFS_MAGIC 0x01021994             /**< tmpfs (in-memory filesystem) */
#define SOCKFS_MAGIC 0x9fa2                /**< Socket pseudo-filesystem */
#define DEBUGFS_MAGIC 0x64626720           /**< Debug filesystem (/sys/kernel/debug) */
#define DEVPTS_SUPER_MAGIC 0x1cd1          /**< devpts (pseudo-terminal devices) */
#define DEVTMPFS_MAGIC 0x74656d70          /**< devtmpfs (/dev) */
#define PIPEFS_MAGIC 0x50495045            /**< Pipe pseudo-filesystem */
#define CGROUP_SUPER_MAGIC 0x27e0eb        /**< Control group filesystem */
#define SELINUX_MAGIC 0xf97cff8c           /**< SELinux filesystem */
#define NFS_SUPER_MAGIC 0x6969             /**< Network File System */
#define AUTOFS_SUPER_MAGIC 0x0187          /**< Automounter filesystem */
#define MQUEUE_MAGIC 0x19800202            /**< POSIX message queue filesystem */
#define FUSE_SUPER_MAGIC 0x65735546        /**< FUSE filesystem */
#define RAMFS_MAGIC 0x858458f6             /**< RAM filesystem */
#define BINFMTFS_MAGIC 0x42494e4d          /**< Binary format handler filesystem */
#define FUTEXFS_SUPER_MAGIC 0xBAD1DEA      /**< Futex filesystem */
#define EVENTPOLLFS_MAGIC 0x19800202       /**< Event poll filesystem */
#define INOTIFYFS_SUPER_MAGIC 0x2BAD1DEA   /**< Inotify filesystem */
#define AIO_RING_MAGIC 0x19800202          /**< Async I/O ring buffer */
#define XENFS_SUPER_MAGIC 0xabba1974       /**< Xen hypervisor filesystem */
#define RPCAUTH_GSSMAGIC 0x67596969        /**< RPC/GSS authentication */
#define OVERLAYFS_SUPER_MAGIC 0x794c7630   /**< OverlayFS (container layers) */
#define TRACEFS_MAGIC 0x74726163           /**< Tracing filesystem (/sys/kernel/tracing) */

/* ============================================================================
 * OPERATION TYPE ENUMERATIONS
 * ============================================================================
 */

/**
 * @brief VFS operation types for I/O event classification
 *
 * These operation types categorize traced filesystem events for analysis.
 * Each traced VFS function maps to one of these operation types.
 */
enum op_type {
  OP_READ = 1,      /**< vfs_read() - Reading data from a file */
  OP_WRITE,         /**< vfs_write() - Writing data to a file */
  OP_OPEN,          /**< vfs_open() - Opening a file descriptor */
  OP_CLOSE,         /**< fput() - Closing/releasing a file descriptor */
  OP_FSYNC,         /**< vfs_fsync() - Flushing file data to storage */
  OP_MMAP,          /**< mmap_region() - Memory-mapping a file */
  OP_MUNMAP,        /**< vm_munmap() - Unmapping memory region */
  OP_GETATTR,       /**< vfs_getattr() - Getting file attributes (stat) */
  OP_SETATTR,       /**< vfs_setattr() - Setting file attributes (chmod, chown) */
  OP_CHDIR,         /**< sys_chdir() - Changing working directory */
  OP_READDIR,       /**< iterate_dir() - Reading directory entries */
  OP_UNLINK,        /**< vfs_unlink() - Deleting a file */
  OP_TRUNCATE,      /**< vfs_truncate() - Truncating file size */
  OP_SYNC,          /**< ksys_sync() - Syncing all filesystems */
  OP_RENAME,        /**< vfs_rename() - Renaming/moving a file */
  OP_MKDIR,         /**< vfs_mkdir() - Creating a directory */
  OP_RMDIR,         /**< vfs_rmdir() - Removing a directory */
  OP_LINK,          /**< vfs_link() - Creating a hard link */
  OP_SYMLINK,       /**< vfs_symlink() - Creating a symbolic link */
  OP_FALLOCATE,     /**< vfs_fallocate() - Pre-allocating file space */
  OP_SENDFILE,      /**< do_sendfile() - Zero-copy send to socket */
  /* Enhanced operations for advanced I/O tracing */
  OP_SPLICE,        /**< splice() - Zero-copy pipe transfer */
  OP_VMSPLICE,      /**< vmsplice() - Splice user pages to pipe */
  OP_MSYNC,         /**< msync() - Sync memory-mapped region */
  OP_MADVISE,       /**< madvise() - Memory usage advice to kernel */
  OP_DIO_READ,      /**< Direct I/O read (bypassing page cache) */
  OP_DIO_WRITE      /**< Direct I/O write (bypassing page cache) */
};

/* ============================================================================
 * DATA STRUCTURES FOR PERF EVENTS
 * ============================================================================
 * These structures define the event data sent to userspace via perf buffers.
 * Each traced operation populates one of these structs before submission.
 */

/**
 * @brief Primary VFS event data structure
 *
 * Contains all information captured for single-path VFS operations
 * (read, write, open, close, etc.). Sent to userspace via events perf buffer.
 */
struct data_t {
  u32 pid;                        /**< Process ID (PID) of the calling process */
  u64 ts;                         /**< Timestamp in nanoseconds (boot time) */
  char comm[TASK_COMM_LEN];       /**< Process name (16 chars max) */
  char filename[FILENAME_MAX_LEN]; /**< Filename from dentry (basename only) */
  u64 inode;                      /**< Inode number for file identification */
  u64 size;                       /**< Operation size in bytes (read/write length) */
  u32 flags;                      /**< File flags (O_RDONLY, O_SYNC, etc.) */
  enum op_type op;                /**< Operation type from op_type enum */
  u64 latency_ns;                 /**< Operation latency in nanoseconds */
  /* Enhanced fields for I/O correlation and analysis */
  u32 fd;                         /**< File descriptor (0 if unavailable in kernel) */
  u64 offset;                     /**< File offset for read/write operations */
  u32 tid;                        /**< Thread ID for multi-threaded correlation */
};

/**
 * @brief Dual-path VFS event data structure
 *
 * Used for operations involving two paths (rename, link, symlink).
 * Larger than data_t due to dual filenames, allocated from per-CPU array
 * to avoid exceeding eBPF stack limit (512 bytes).
 */
struct data_dual_t {
  u32 pid;                            /**< Process ID of the calling process */
  u64 ts;                             /**< Timestamp in nanoseconds */
  char comm[TASK_COMM_LEN];           /**< Process name */
  char filename_old[FILENAME_MAX_LEN]; /**< Source/old filename (rename src, link target) */
  char filename_new[FILENAME_MAX_LEN]; /**< Destination/new filename */
  u64 inode_old;                      /**< Source inode number */
  u64 inode_new;                      /**< Destination inode number */
  u32 flags;                          /**< Operation-specific flags */
  enum op_type op;                    /**< Operation type (RENAME, LINK, SYMLINK) */
  u64 latency_ns;                     /**< Operation latency */
};

/**
 * @brief Kernel renamedata structure (kernel 5.12+)
 *
 * Used by vfs_rename() in modern kernels. We define a minimal version
 * to extract the dentry pointers we need.
 */
struct renamedata_bpf {
  void *old_mnt_idmap;
  struct inode *old_dir;
  struct dentry *old_dentry;
  void *new_mnt_idmap;
  struct inode *new_dir;
  struct dentry *new_dentry;
  /* remaining fields not needed */
};

/**
 * @brief Block layer I/O event data structure
 *
 * Captures block device I/O requests with latency tracking.
 * Tracks the complete lifecycle: insert -> issue -> complete.
 */
struct block_event {
  u64 ts;                   /**< Completion timestamp in nanoseconds */
  u32 pid;                  /**< Process ID that submitted the request */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 sector;               /**< Starting sector number on disk */
  char op[OP_LEN];          /**< Operation type string ("R", "W", "RA", "WS") */
  u32 tid;                  /**< Thread ID */
  u32 cpu_id;               /**< CPU where completion was processed */
  u32 ppid;                 /**< Parent process ID */
  u32 flags;                /**< Request flags (reserved) */
  u64 bio_size;             /**< I/O size in bytes (sectors * 512) */
  u64 latency_ns;           /**< Time from issue to completion (device latency) */
  u32 dev;                  /**< Device number (major:minor encoded) for partition ID */
  u64 queue_time_ns;        /**< Time from insert to issue (scheduler latency) */
};

/* ============================================================================
 * PAGE FAULT TRACING STRUCTURES
 * ============================================================================
 * Tracks memory-mapped file I/O by monitoring page faults that trigger
 * actual disk reads (major faults) or page cache access (minor faults).
 */

/** @brief Page fault access type */
enum pagefault_type {
  FAULT_READ = 0,   /**< Read access triggered the fault */
  FAULT_WRITE = 1   /**< Write access triggered the fault */
};

/**
 * @brief Page fault event data structure
 *
 * Captures file-backed page faults that occur when accessing
 * memory-mapped files. Major faults indicate actual disk I/O.
 */
struct pagefault_data {
  u64 ts;                   /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID */
  u32 tid;                  /**< Thread ID */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 address;              /**< Faulting virtual address */
  u64 inode;                /**< Backing file inode (0 if anonymous mapping) */
  u64 offset;               /**< File offset in pages (pgoff) */
  u8 fault_type;            /**< FAULT_READ or FAULT_WRITE */
  u8 major;                 /**< 0=minor (cached), 1=major (disk read) */
  u32 dev_id;               /**< Device ID from file's superblock */
};

/* ============================================================================
 * IO_URING STRUCTURES
 * ============================================================================
 * io_uring is the modern async I/O interface in Linux (5.1+).
 * It allows batching multiple I/O operations with single syscall overhead.
 */

/**
 * @brief io_uring operation types
 *
 * Subset of IORING_OP_* opcodes for categorizing async I/O operations.
 * Full list in include/uapi/linux/io_uring.h
 */
enum iouring_op {
  IORING_OP_NOP = 0,              /**< No operation (for testing) */
  IORING_OP_READV = 1,            /**< Vectored read */
  IORING_OP_WRITEV = 2,           /**< Vectored write */
  IORING_OP_FSYNC = 3,            /**< Fsync file */
  IORING_OP_READ_FIXED = 4,       /**< Read with registered buffers */
  IORING_OP_WRITE_FIXED = 5,      /**< Write with registered buffers */
  IORING_OP_POLL_ADD = 6,         /**< Add poll request */
  IORING_OP_POLL_REMOVE = 7,      /**< Remove poll request */
  IORING_OP_SYNC_FILE_RANGE = 8,  /**< Sync file range */
  IORING_OP_SENDMSG = 9,          /**< Send message on socket */
  IORING_OP_RECVMSG = 10,         /**< Receive message from socket */
  IORING_OP_TIMEOUT = 11,         /**< Set timeout */
  IORING_OP_TIMEOUT_REMOVE = 12,  /**< Remove timeout */
  IORING_OP_ACCEPT = 13,          /**< Accept connection */
  IORING_OP_ASYNC_CANCEL = 14,    /**< Cancel async operation */
  IORING_OP_LINK_TIMEOUT = 15,    /**< Linked timeout */
  IORING_OP_CONNECT = 16,
  IORING_OP_FALLOCATE = 17,
  IORING_OP_OPENAT = 18,
  IORING_OP_CLOSE = 19,
  IORING_OP_READ = 22,
  IORING_OP_WRITE = 23,
  IORING_OP_FADVISE = 24,
  IORING_OP_MADVISE = 25,
  IORING_OP_SEND = 26,
  IORING_OP_RECV = 27,
  IORING_OP_STATX = 28            /**< Get extended file attributes */
};

/**
 * @brief io_uring event data structure
 *
 * Captures async I/O submissions and completions through io_uring.
 */
struct iouring_data {
  u64 ts;                   /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u8 opcode;                /**< IORING_OP_* opcode (255 = io_uring_enter itself) */
  u32 fd;                   /**< File descriptor for the operation */
  u64 offset;               /**< File offset for positioned I/O */
  u32 len;                  /**< Number of operations (for io_uring_enter) */
  s32 result;               /**< Operation result/return value */
  u64 latency_ns;           /**< Operation latency */
  u64 inode;                /**< File inode if available */
};

/* ============================================================================
 * PAGE CACHE TRACING STRUCTURES
 * ============================================================================
 * The page cache buffers disk I/O in memory. These structures track
 * cache efficacy: hits reduce disk reads, misses cause disk I/O.
 */

/**
 * @brief Page cache event types
 *
 * Categorizes page cache lifecycle events from allocation to eviction.
 */
enum cache_event_type {
  CACHE_HIT = 0,            /**< Page found in cache (no disk I/O) */
  CACHE_MISS = 1,           /**< Page not in cache (disk read required) */
  CACHE_DIRTY = 2,          /**< Page marked dirty (modified, needs writeback) */
  CACHE_WRITEBACK_START = 3, /**< Dirty page writeback initiated */
  CACHE_WRITEBACK_END = 4,  /**< Dirty page writeback completed */
  CACHE_EVICT = 5,          /**< Page evicted from cache (memory pressure) */
  CACHE_INVALIDATE = 6,     /**< Pages explicitly invalidated (truncate, drop) */
  CACHE_DROP = 7,           /**< Page dropped via invalidation */
  CACHE_READAHEAD = 8,      /**< Prefetch/readahead pages loaded */
  CACHE_RECLAIM = 9,        /**< Memory reclaim event (kswapd/direct) */
};

/**
 * @brief Page cache event data structure
 *
 * Contains metadata about page cache operations for analysis
 * of cache hit rates, writeback patterns, and memory pressure.
 */
struct cache_data {
  u64 ts;                   /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID that triggered the event */
  u8 type;                  /**< Event type from cache_event_type enum */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 inode;                /**< File inode number */
  u64 index;                /**< Page index (file offset / PAGE_SIZE) */
  u32 size;                 /**< File size in pages (populated by helper) */
  u32 cpu_id;               /**< CPU where event occurred */
  u32 dev_id;               /**< Device ID from superblock */
  u32 count;                /**< Number of pages (for batch operations) */
};

/* ============================================================================
 * NETWORK I/O STRUCTURES
 * ============================================================================
 * Tracks TCP and UDP network traffic for correlation with file I/O.
 */

/** @brief Network I/O direction */
enum direction_t {
  DIR_SEND = 0,   /**< Outgoing data (sendmsg) */
  DIR_RECV = 1    /**< Incoming data (recvmsg) */
};

/**
 * @brief Network I/O event data structure
 *
 * Captures TCP/UDP send and receive operations with connection info.
 * Supports both IPv4 and IPv6 addresses.
 */
struct network_data {
  u64 ts_ns;                /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u8 ipver;                 /**< IP version: 4 or 6 */
  u8 proto;                 /**< Protocol: 6=TCP, 17=UDP (IPPROTO_*) */
  u8 dir;                   /**< Direction: DIR_SEND or DIR_RECV */
  u16 sport;                /**< Source port (host byte order) */
  u16 dport;                /**< Destination port (host byte order) */
  /* IPv4 addresses (only valid when ipver==4) */
  u32 saddr_v4;             /**< Source IPv4 address */
  u32 daddr_v4;             /**< Destination IPv4 address */
  /* IPv6 addresses (only valid when ipver==6) */
  unsigned __int128 saddr_v6; /**< Source IPv6 address */
  unsigned __int128 daddr_v6; /**< Destination IPv6 address */
  u32 size_bytes;           /**< Data size in bytes */
};

/**
 * @brief VFS operation context for latency tracking
 *
 * Stores entry context for VFS operations that need return probe correlation.
 */
struct vfs_info {
  u64 start_ts;       /**< Entry timestamp for latency calculation */
  struct file *file;  /**< File pointer captured at entry */
  size_t size;        /**< Requested operation size */
  loff_t *pos;        /**< File position pointer */
  enum op_type op;    /**< Operation type for return probe */
};

/* ============================================================================
 * BPF MAPS
 * ============================================================================
 * BPF maps store state and configuration. Hash maps allow O(1) lookup,
 * per-CPU arrays avoid lock contention, perf buffers stream events.
 */

/* Block layer latency tracking maps */
BPF_HASH(block_start_times, u64, u64);   /**< Tracks block request issue time */
BPF_HASH(block_insert_times, u64, u64);  /**< Tracks block request insert time (queue latency) */

/* VFS operation tracking maps */
BPF_HASH(start, u64, u64);               /**< Generic operation start times */
BPF_HASH(file_positions, u64, u64, 1024); /**< File position cache for offset tracking */

/* Configuration map - stores tracer PID to exclude self-tracing */
BPF_HASH(tracer_config, u32, u32, 1);    /**< Key 0 = tracer PID to exclude */

/* Network receive context - stores socket for kretprobe correlation */
BPF_HASH(tcp_recv_ctx, u64, struct sock *); /**< TCP recvmsg entry context */
BPF_HASH(udp_recv_ctx, u64, struct sock *); /**< UDP recvmsg entry context */

/* Async I/O tracking maps */
BPF_HASH(iouring_start, u64, u64);       /**< io_uring request start times */
BPF_HASH(dio_start, u64, u64);           /**< Direct I/O operation start times */

/* Per-CPU buffer for large structs that exceed 512-byte stack limit */
BPF_PERCPU_ARRAY(dual_data_buffer, struct data_dual_t, 1);

/* ============================================================================
 * PERF OUTPUT BUFFERS
 * ============================================================================
 * Perf buffers stream event data to userspace with minimal overhead.
 * Each buffer type corresponds to a specific event category.
 */

BPF_PERF_OUTPUT(events);            /**< VFS single-path events (data_t) */
BPF_PERF_OUTPUT(events_dual);       /**< VFS dual-path events (data_dual_t) */
BPF_PERF_OUTPUT(bl_events);         /**< Block layer events (block_event) */
BPF_PERF_OUTPUT(cache_events);      /**< Page cache events (cache_data) */
BPF_PERF_OUTPUT(net_events);        /**< Network I/O events (network_data) */
BPF_PERF_OUTPUT(pagefault_events);  /**< Memory-mapped page faults (pagefault_data) */
BPF_PERF_OUTPUT(iouring_events);    /**< io_uring async I/O events (iouring_data) */

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================
 * Static inline helpers for common operations. __always_inline ensures
 * these are inlined to avoid BPF function call overhead.
 */

/**
 * @brief Extract IP addresses and ports from a socket structure
 *
 * Reads connection 4-tuple (src/dst IP and port) from socket.
 * Handles both IPv4 and IPv6 address families.
 *
 * @param sk   Kernel socket structure
 * @param e    Network event structure to populate
 * @return     0 on success, -1 if unsupported address family
 */
static __always_inline int read_addrs_ports(struct sock *sk,
                                            struct network_data *e) {
  u16 family = sk->__sk_common.skc_family;
  if (family == AF_INET) {
    e->ipver = 4;
    struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;

    bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), &inet->inet_dport);

    e->saddr_v4 = saddr;
    e->daddr_v4 = daddr;
    e->sport = bpf_ntohs(sport);
    e->dport = bpf_ntohs(dport);
    return 0;
  } else if (family == AF_INET6) {
    e->ipver = 6;
    // Try to read from skc_v6_* in __sk_common if available
    // This is more stable across kernels than inet6_sk() fields in BPF
    unsigned __int128 saddr6 = 0, daddr6 = 0;
    u16 sport = 0, dport = 0;

    bpf_probe_read_kernel(&saddr6, sizeof(saddr6),
                          &sk->__sk_common.skc_v6_rcv_saddr.in6_u);
    bpf_probe_read_kernel(&daddr6, sizeof(daddr6),
                          &sk->__sk_common.skc_v6_daddr.in6_u);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->saddr_v6 = saddr6;
    e->daddr_v6 = daddr6;
    e->sport = sport;            // skc_num already host order
    e->dport = bpf_ntohs(dport); // skc_dport is network order
    return 0;
  }
  return -1;
}

/**
 * @brief Fill common fields in network event structure
 *
 * Populates timestamp, PID, process name, and network metadata.
 *
 * @param e     Network event structure to populate
 * @param proto IP protocol number (6=TCP, 17=UDP)
 * @param dir   Direction (DIR_SEND or DIR_RECV)
 * @param size  Data size in bytes
 */
static __always_inline void fill_common(struct network_data *e, u8 proto,
                                        u8 dir, u32 size) {
  e->ts_ns = bpf_ktime_get_ns();
  u64 pid_tgid = bpf_get_current_pid_tgid();
  e->pid = pid_tgid >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->proto = proto;
  e->dir = dir;
  e->size_bytes = size;
}

/**
 * @brief Get inode number from a file structure
 *
 * Safely traverses file->f_path.dentry->d_inode->i_ino
 *
 * @param file  Kernel file structure pointer
 * @return      Inode number, or 0 if unavailable
 */
static u64 get_file_inode(struct file *file) {
  u64 inode = 0;
  if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
    inode = file->f_path.dentry->d_inode->i_ino;
  }
  return inode;
}

/**
 * @brief Check if a file is a regular file (not virtual/pseudo filesystem)
 *
 * Filters out pseudo-filesystems (proc, sys, devtmpfs, etc.) to focus
 * tracing on real storage I/O. Uses filesystem magic numbers for detection.
 *
 * @param file  Kernel file structure pointer
 * @return      true if regular file on real filesystem, false otherwise
 */
static bool is_regular_file(struct file *file) {
  bool is_reg, is_virtual;
  if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode ||
      !file->f_path.dentry->d_sb) {
    return false;
  }
  umode_t mode;
  bpf_probe_read_kernel(&mode, sizeof(mode),
                        &file->f_path.dentry->d_inode->i_mode);
  is_reg = S_ISREG(mode);  /* Check if regular file (not dir/socket/pipe) */

  struct super_block *sb = file->f_path.dentry->d_sb;
  unsigned long magic = 0;
  bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);

  switch (magic) {
  case PROC_SUPER_MAGIC:
  case SYSFS_MAGIC:
  case TMPFS_MAGIC:
  case SOCKFS_MAGIC:
  case DEBUGFS_MAGIC:
  case DEVPTS_SUPER_MAGIC:
  case DEVTMPFS_MAGIC:
  case PIPEFS_MAGIC:
  case CGROUP_SUPER_MAGIC:
  case SELINUX_MAGIC:
  case FUTEXFS_SUPER_MAGIC:
  case INOTIFYFS_SUPER_MAGIC:
  case XENFS_SUPER_MAGIC:
  case RPCAUTH_GSSMAGIC:
  case TRACEFS_MAGIC:
  case 0x19800202:
    is_virtual = true;
    break;
  default:
    is_virtual = false;
  }

  return is_reg && !is_virtual;
}

/**
 * @brief Extract filename from file structure
 *
 * Gets the basename (not full path) from the file's dentry.
 * Full path reconstruction requires expensive dentry walking.
 *
 * @param file  Kernel file structure
 * @param buf   Output buffer for filename
 * @param size  Buffer size
 * @return      0 on success
 */
static int get_file_path(struct file *file, char *buf, int size) {
  struct dentry *dentry;

  // Safety check for file pointer
  if (!file) {
    // Mark as anonymous or pipe
    __builtin_memcpy(buf, "", 1);
    return 0;
  }

  dentry = file->f_path.dentry;
  if (!dentry) {
    __builtin_memcpy(buf, "", 1);
    return 0;
  }

  struct super_block *sb = dentry->d_sb;
  unsigned long magic = 0;
  if (sb) {
    bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);
  }

  const unsigned char *name_ptr;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

  if (name_ptr) {
    ssize_t len = bpf_probe_read_kernel_str(buf, size, name_ptr);
    volatile char first_char = buf[0];
    if (len <= 0 || first_char == '\0') {
      __builtin_memcpy(buf, "", 1);
    }
  } else {
    __builtin_memcpy(buf, "", 1);
  }

  return 0;
}

/**
 * @brief Get inode number from a dentry structure
 *
 * @param dentry  Kernel dentry structure
 * @return        Inode number, or 0 if unavailable
 */
static u64 get_file_inode_from_dentry(struct dentry *dentry) {
  u64 inode = 0;
  if (dentry && dentry->d_inode) {
    inode = dentry->d_inode->i_ino;
  }
  return inode;
}

/**
 * @brief Extract filename from dentry structure
 *
 * Gets the filename component from a dentry's d_name.
 *
 * @param dentry  Kernel dentry structure
 * @param buf     Output buffer for filename
 * @param size    Buffer size
 * @return        0 on success
 */
static int get_file_path_from_dentry(struct dentry *dentry, char *buf,
                                     int size) {
  if (!dentry) {
    __builtin_memcpy(buf, "[no_dentry]", 12);
    return 0;
  }

  const unsigned char *name_ptr;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

  if (name_ptr) {
    bpf_probe_read_kernel_str(buf, size, name_ptr);
  } else {
    buf[0] = '\0';  // Empty string - fixed from broken memcpy
  }

  return 0;
}

/**
 * @brief Populate cache event metadata from inode
 *
 * Extracts file size (in pages), device ID, and sets default count.
 *
 * @note Filename cannot be reliably resolved from inode alone in eBPF
 *       because inode->i_dentry is a list requiring complex iteration.
 *       The filename field must be populated before calling if needed.
 *
 * @param data   Cache event structure to populate
 * @param inode  Kernel inode structure
 */
static void populate_cache_metadata(struct cache_data *data, struct inode *inode) {
  if (!inode || !data) {
    return;
  }
  
  // Try to get file size in pages
  loff_t file_size = 0;
  bpf_probe_read_kernel(&file_size, sizeof(file_size), &inode->i_size);
  data->size = (u32)(file_size >> PAGE_SHIFT);  // Convert bytes to number of pages
  
  // Get device ID from superblock
  struct super_block *sb = NULL;
  bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
  if (sb) {
    bpf_probe_read_kernel(&data->dev_id, sizeof(data->dev_id), &sb->s_dev);
  }
  
  // Set count to 1 for single-page operations if not already set
  if (data->count == 0) {
    data->count = 1;
  }
}

/* ============================================================================
 * VFS OPERATION PROBES
 * ============================================================================
 * These kprobes attach to VFS (Virtual File System) layer functions to
 * capture file I/O operations at the filesystem-agnostic layer.
 */

/**
 * @brief Trace vfs_read() - VFS read operations
 *
 * Captures file read operations including offset and size.
 * Filters out virtual filesystems and tracer's own PID.
 *
 * @param ctx   BPF context with registers
 * @param file  File being read
 * @param buf   Userspace buffer (not used)
 * @param count Bytes to read
 * @param pos   File position pointer
 * @return      0 (continue execution)
 */
int trace_vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf,
                   size_t count, loff_t *pos) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_READ;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
  
  // Capture file offset
  if (pos) {
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
  }
  
  // FD is not directly available from struct file in kernel context
  // We capture 0 to indicate it needs user-space correlation
  data.fd = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_write() - VFS write operations
 *
 * Captures file write operations with offset tracking.
 *
 * @param ctx   BPF context
 * @param file  File being written
 * @param buf   Userspace data buffer (not accessed)
 * @param count Bytes to write
 * @param pos   File position pointer
 * @return      0
 */
int trace_vfs_write(struct pt_regs *ctx, struct file *file,
                    const char __user *buf, size_t count, loff_t *pos) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_WRITE;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
  
  // Capture file offset
  if (pos) {
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
  }
  
  data.fd = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_open() - VFS file open operations
 *
 * Captures file opens with flags (O_RDONLY, O_WRONLY, O_SYNC, etc.).
 * Does not filter by file type to catch all opens.
 *
 * @param ctx   BPF context
 * @param path  Path being opened
 * @param file  Newly allocated file structure
 * @return      0
 */
int trace_vfs_open(struct pt_regs *ctx, const struct path *path,
                   struct file *file) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  // if (!is_regular_file(file)) {
  //     return 0;
  // }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_OPEN;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_fsync() - File synchronization
 *
 * Captures fsync/fdatasync calls that flush data to storage.
 * datasync flag distinguishes fsync (0) from fdatasync (1).
 *
 * @param ctx      BPF context
 * @param file     File being synced
 * @param datasync 0 for fsync, 1 for fdatasync
 * @return         0
 */
int trace_vfs_fsync(struct pt_regs *ctx, struct file *file, int datasync) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_FSYNC;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_fsync_range() - Range-based file synchronization
 *
 * Captures sync_file_range() calls with byte offset range.
 * Size field contains the range size being synced.
 *
 * @param ctx      BPF context
 * @param file     File being synced
 * @param start    Start offset in bytes
 * @param end      End offset (LLONG_MAX means to EOF)
 * @param datasync Sync type flag
 * @return         0
 */
int trace_vfs_fsync_range(struct pt_regs *ctx, struct file *file, loff_t start,
                          loff_t end, int datasync) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  loff_t range_size;
  loff_t file_size = 0;
  if (file && file->f_inode) {
    bpf_probe_read_kernel(&file_size, sizeof(file_size),
                          &file->f_inode->i_size);
  }

  if (end == LLONG_MAX) {
    range_size = file_size - start;
  } else {
    range_size = end - start;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_FSYNC;
  data.inode = get_file_inode(file);
  data.size = range_size;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace fput() - File descriptor close/release
 *
 * Captures when file descriptors are released (reference count drops).
 * This is the actual close, not close() syscall entry.
 *
 * @param ctx   BPF context
 * @param file  File being released
 * @return      0
 */
int trace_fput(struct pt_regs *ctx, struct file *file) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_CLOSE;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace mmap file mappings
 *
 * Captures memory-mapped file regions. Protection and flags are combined
 * in the flags field (prot in low 16 bits, flags in high 16 bits).
 *
 * @param ctx   BPF context
 * @param file  File being mapped (NULL for anonymous mappings)
 * @param addr  Requested mapping address
 * @param len   Mapping length in bytes
 * @param prot  Protection flags (PROT_READ, PROT_WRITE, etc.)
 * @param flags Mapping flags (MAP_SHARED, MAP_PRIVATE, etc.)
 * @return      0
 */
int trace_mmap(struct pt_regs *ctx, struct file *file, unsigned long addr,
               unsigned long len, unsigned long prot, unsigned long flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!file || !is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MMAP;
  data.inode = get_file_inode(file);
  data.size = len;
  get_file_path(file, data.filename, sizeof(data.filename));
  data.flags = (u32)prot | ((u32)flags << 16);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace munmap() - Memory unmapping
 *
 * Captures memory region unmappings. Does not have file context.
 *
 * @param ctx  BPF context
 * @param addr Start address being unmapped
 * @param len  Length being unmapped
 * @return     0
 */
int trace_munmap(struct pt_regs *ctx, unsigned long addr, size_t len) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MUNMAP;
  data.inode = 0;
  data.size = len;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_getattr() - File attribute queries (stat)
 *
 * Captures stat(), lstat(), fstat() calls for file metadata access.
 *
 * @param ctx          BPF context
 * @param path         Path being queried
 * @param stat         Output stat buffer
 * @param request_mask Requested attributes mask
 * @param query_flags  Query flags
 * @return             0
 */
int trace_vfs_getattr(struct pt_regs *ctx, const struct path *path,
                      struct kstat *stat, u32 request_mask,
                      unsigned int query_flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!path || !path->dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_GETATTR;
  data.inode = get_file_inode_from_dentry(path->dentry);
  data.size = 0;
  get_file_path_from_dentry(path->dentry, data.filename, sizeof(data.filename));
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_setattr() - File attribute modifications
 *
 * Captures chmod(), chown(), utimes() and similar operations.
 *
 * @param ctx     BPF context
 * @param dentry  Dentry being modified
 * @param attr    New attributes to set
 * @return        0
 */
int trace_vfs_setattr(struct pt_regs *ctx, struct dentry *dentry,
                      struct iattr *attr) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SETATTR;
  data.inode = get_file_inode_from_dentry(dentry);
  data.size = 0;
  get_file_path_from_dentry(dentry, data.filename, sizeof(data.filename));
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace chdir syscall - Working directory changes
 *
 * Tracepoint probe for chdir() syscall entry.
 * Filename field contains the target directory path.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_CHDIR;
  data.inode = 0;
  data.size = 0;

  bpf_probe_read_user_str(data.filename, sizeof(data.filename),
                          (void *)args->filename);
  data.flags = 0;

  events.perf_submit(args, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace iterate_dir() - Directory reading
 *
 * Captures getdents/readdir operations on directories.
 *
 * @param ctx      BPF context
 * @param file     Directory file being read
 * @param ctx_dir  Directory iteration context
 * @return         0
 */
int trace_readdir(struct pt_regs *ctx, struct file *file,
                  struct dir_context *ctx_dir) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_READDIR;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_unlink() - File deletion
 *
 * Captures file unlink operations (removing directory entries).
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  Dentry being unlinked
 * @return        0
 */
int trace_vfs_unlink(struct pt_regs *ctx, struct inode *dir,
                     struct dentry *dentry) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_UNLINK;

  if (dentry && dentry->d_inode) {
    bpf_probe_read_kernel(&data.inode, sizeof(data.inode),
                          &dentry->d_inode->i_ino);
  }

  get_file_path_from_dentry(dentry, data.filename, sizeof(data.filename));

  data.size = 0;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_truncate() - File size truncation
 *
 * Captures truncate()/ftruncate() operations that change file size.
 *
 * @param ctx   BPF context
 * @param path  Path being truncated
 * @return      0
 */
int trace_vfs_truncate(struct pt_regs *ctx, const struct path *path) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_TRUNCATE;

  if (path && path->dentry && path->dentry->d_inode) {
    bpf_probe_read_kernel(&data.inode, sizeof(data.inode),
                          &path->dentry->d_inode->i_ino);
  }

  if (path && path->dentry) {
    get_file_path_from_dentry(path->dentry, data.filename, sizeof(data.filename));
  }

  data.size = 0;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace ksys_sync() - System-wide sync
 *
 * Captures sync() syscall that flushes all filesystem buffers.
 *
 * @param ctx  BPF context
 * @return     0
 */
int trace_ksys_sync(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SYNC;
  data.inode = 0;
  data.size = 0;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/* ============================================================================
 * DUAL-PATH FILESYSTEM OPERATION PROBES
 * ============================================================================
 * Operations involving two paths (source and destination) use the larger
 * data_dual_t structure allocated from per-CPU array.
 */

/**
 * @brief Trace vfs_rename() - File/directory rename
 *
 * Captures rename()/renameat() operations with source and destination paths.
 * Uses per-CPU buffer for the 572-byte data_dual_t structure.
 * Kernel 6.x signature: vfs_rename(struct renamedata *rd)
 *
 * @param ctx  BPF context
 * @param rd   Rename data structure containing old/new dentry info
 * @return     0
 */
int trace_vfs_rename(struct pt_regs *ctx, struct renamedata_bpf *rd) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!rd) {
    return 0;
  }

  // Read dentry pointers from renamedata struct
  struct dentry *old_dentry = NULL;
  struct dentry *new_dentry = NULL;
  bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
  bpf_probe_read_kernel(&new_dentry, sizeof(new_dentry), &rd->new_dentry);

  if (!old_dentry || !new_dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit (data_dual_t is 572 bytes, stack limit is 512)
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_RENAME;

  // Get old path and inode
  data->inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data->filename_old, sizeof(data->filename_old));

  // Get new path and inode
  data->inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data->filename_new, sizeof(data->filename_new));

  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_mkdir() - Directory creation
 *
 * Captures mkdir() operations. Mode field contains permission bits.
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  New directory dentry
 * @param mode    Permission mode (e.g., 0755)
 * @return        0
 */
int trace_vfs_mkdir(struct pt_regs *ctx, struct inode *dir,
                    struct dentry *dentry, umode_t mode) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MKDIR;
  data.inode = get_file_inode_from_dentry(dentry);
  data.size = 0;
  get_file_path_from_dentry(dentry, data.filename, sizeof(data.filename));
  data.flags = mode;
  data.latency_ns = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_rmdir() - Directory removal
 *
 * Captures rmdir() operations.
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  Directory being removed
 * @return        0
 */
int trace_vfs_rmdir(struct pt_regs *ctx, struct inode *dir,
                    struct dentry *dentry) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_RMDIR;
  data.inode = get_file_inode_from_dentry(dentry);
  data.size = 0;
  get_file_path_from_dentry(dentry, data.filename, sizeof(data.filename));
  data.flags = 0;
  data.latency_ns = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_link() - Hard link creation
 *
 * Captures link() operations. Both dentries will share the same inode.
 * Kernel 6.x signature: vfs_link(old_dentry, mnt_idmap, dir, new_dentry, ...)
 *
 * @param ctx         BPF context
 * @param old_dentry  Existing file dentry
 * @param idmap       Mount ID map (kernel 6.x)
 * @param dir         Directory where link is created
 * @param new_dentry  New link dentry
 * @return            0
 */
int trace_vfs_link(struct pt_regs *ctx, struct dentry *old_dentry,
                   void *idmap, struct inode *dir, struct dentry *new_dentry) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!old_dentry || !new_dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_LINK;

  // Get old path and inode
  data->inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data->filename_old, sizeof(data->filename_old));

  // Get new path and inode
  data->inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data->filename_new, sizeof(data->filename_new));

  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_symlink() - Symbolic link creation
 *
 * Captures symlink() operations. filename_old contains target path,
 * filename_new contains the symlink name.
 * Kernel 6.x signature: vfs_symlink(mnt_idmap, dir, dentry, oldname)
 *
 * @param ctx     BPF context
 * @param idmap   Mount ID map (kernel 6.x)
 * @param dir     Directory where symlink is created
 * @param dentry  New symlink dentry
 * @param oldname Target path (symlink content)
 * @return        0
 */
int trace_vfs_symlink(struct pt_regs *ctx, void *idmap, struct inode *dir,
                      struct dentry *dentry, const char *oldname) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_SYMLINK;
  
  // filename_old is the target of the symlink (try user pointer first, then kernel)
  if (oldname) {
    int ret = bpf_probe_read_user_str(data->filename_old, sizeof(data->filename_old), oldname);
    if (ret <= 0) {
      bpf_probe_read_kernel_str(data->filename_old, sizeof(data->filename_old), oldname);
    }
  }
  
  // filename_new is the link name
  get_file_path_from_dentry(dentry, data->filename_new, sizeof(data->filename_new));
  
  data->inode_old = 0;
  data->inode_new = get_file_inode_from_dentry(dentry);
  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_fallocate() - File space pre-allocation
 *
 * Captures fallocate() calls for pre-allocating disk space.
 * Mode field contains FALLOC_FL_* flags.
 *
 * @param ctx    BPF context
 * @param file   File to allocate space for
 * @param mode   Allocation mode flags
 * @param offset Starting offset
 * @param len    Length to allocate
 * @return       0
 */
int trace_vfs_fallocate(struct pt_regs *ctx, struct file *file, int mode,
                        loff_t offset, loff_t len) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_FALLOCATE;
  data.inode = get_file_inode(file);
  data.size = len;
  get_file_path(file, data.filename, sizeof(data.filename));
  data.flags = mode;
  data.latency_ns = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace sendfile() - Zero-copy file-to-socket transfer
 *
 * Captures sendfile() operations for efficient file serving.
 * Does not have direct access to file structures, only FDs.
 *
 * @param ctx    BPF context
 * @param out_fd Destination (socket) file descriptor
 * @param in_fd  Source (file) file descriptor
 * @param offset File offset for reading
 * @param count  Bytes to transfer
 * @return       0
 */
int trace_sendfile(struct pt_regs *ctx, int out_fd, int in_fd, loff_t *offset,
                   size_t count) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SENDFILE;
  data.inode = 0;
  data.size = count;
  __builtin_memcpy(data.filename, "[sendfile]", 11);
  data.flags = 0;
  data.latency_ns = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * BLOCK LAYER TRACEPOINTS
 * ============================================================================
 * Block layer tracing captures disk I/O at the request queue level.
 * Three events track request lifecycle: insert -> issue -> complete
 */

/**
 * @brief Block request insert tracepoint
 *
 * Records when a request enters the I/O scheduler queue.
 * Used to calculate queue time (insert to issue latency).
 */
TRACEPOINT_PROBE(block, block_rq_insert) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Store insert timestamp for queue time calculation
  u64 key = ((u64)args->dev << 32) ^ (u64)args->sector;
  u64 ts = bpf_ktime_get_ns();
  block_insert_times.update(&key, &ts);

  return 0;
}

/**
 * @brief Block request issue tracepoint
 *
 * Records when a request is submitted to the device driver.
 * Start time is stored for latency calculation on completion.
 * Key is composite of device and sector for cross-CPU correlation.
 */
TRACEPOINT_PROBE(block, block_rq_issue) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Use dev and sector as key to correlate issue with completion
  // Note: CPU ID is NOT included because completion may occur on a different CPU
  u64 key = ((u64)args->dev << 32) ^ (u64)args->sector;
  u64 ts = bpf_ktime_get_ns();
  block_start_times.update(&key, &ts);

  return 0;
}

/**
 * @brief Block request completion tracepoint
 *
 * Records when I/O completes, calculates latencies, and emits event.
 * Computes both device latency (issue->complete) and queue latency.
 */
TRACEPOINT_PROBE(block, block_rq_complete) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Use dev and sector to match the key from block_rq_issue
  u64 key = ((u64)args->dev << 32) | (args->sector & 0xFFFFFFFF);
  u64 *start_ts = block_start_times.lookup(&key);
  if (!start_ts)
    return 0;

  u64 end_ts = bpf_ktime_get_ns();
  u64 latency = end_ts - *start_ts;
  
  // Calculate queue time (time from insert to issue)
  u64 queue_time = 0;
  u64 *insert_ts = block_insert_times.lookup(&key);
  if (insert_ts && *start_ts >= *insert_ts) {
    queue_time = *start_ts - *insert_ts;
  }

  struct block_event event = {};
  event.ts = end_ts;
  event.pid = pid;
  event.tid = bpf_get_current_pid_tgid();
  event.cpu_id = bpf_get_smp_processor_id();
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Get parent PID
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = NULL;
  if (task) {
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
      bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
    }
  }

  event.sector = args->sector;
  
  // Calculate bio_size (nr_sector is u32, so shifting by 9 never overflows u64)
  event.bio_size = ((u64)args->nr_sector) << 9;
  
  event.latency_ns = latency;
  event.queue_time_ns = queue_time;  // New: queue time
  event.flags = 0;  // Reserved for future use
  
  // Capture device number for partition identification
  // dev contains major:minor encoding (major in bits 8-15, minor in bits 0-7 on older kernels,
  // or major in bits 8-15, minor in bits 0-15 with extensions on newer kernels)
  event.dev = args->dev;

  bpf_probe_read_kernel(&event.op, sizeof(event.op), &args->rwbs);

  bl_events.perf_submit(args, &event, sizeof(event));

  block_start_times.delete(&key);
  block_insert_times.delete(&key);
  return 0;
}

/**
 * @brief Helper to read filename from dentry
 *
 * @param dentry  Dentry to read from
 * @param buf     Output buffer
 * @return        0
 */
static int get_filename(struct dentry *dentry, char *buf) {
  struct qstr d_name = dentry->d_name;
  bpf_probe_read_kernel_str(buf, DNAME_INLINE_LEN, d_name.name);
  return 0;
}

/* ============================================================================
 * PAGE CACHE PROBES
 * ============================================================================
 * Page cache probes track memory-cached file pages. Kernel 5.16+ uses
 * "folio" (multi-page unit), older kernels use "page" structures.
 */

/**
 * @brief Cache hit probe - folio version (kernel >= 5.16)
 *
 * folio_mark_accessed() is called when a cached page is accessed.
 * Indicates data was served from cache without disk I/O.
 */
int trace_folio_mark_accessed(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_HIT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    // Read index first so populate_cache_metadata can calculate offset
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);
    
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache hit probe - page version (kernel < 5.17)
 *
 * mark_page_accessed() for older kernels without folio API.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_hit(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_HIT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    // Read index first so populate_cache_metadata can calculate offset
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);
    
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache miss probe - folio version (kernel >= 5.16)
 *
 * filemap_add_folio() adds a new page to cache after disk read.
 * This indicates a cache miss that required actual disk I/O.
 */
int trace_filemap_add_folio(struct pt_regs *ctx, struct address_space *mapping,
                            struct folio *folio, pgoff_t index, gfp_t gfp) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_MISS;
  data.index = index;  // Set before calling populate_cache_metadata
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache miss probe - page version (kernel < 5.17)
 *
 * add_to_page_cache_lru() for older kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_miss(struct pt_regs *ctx, struct page *page,
               struct address_space *mapping, pgoff_t offset, gfp_t gfp_mask) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_MISS;
  data.index = offset;  // Set before calling populate_cache_metadata
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Dirty page probe - page version (kernel < 5.17)
 *
 * account_page_dirtied() marks a page as modified.
 * Dirty pages need writeback before eviction.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_account_page_dirtied(struct pt_regs *ctx, struct page *page,
                               struct address_space *mapping) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DIRTY;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);
  }

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Dirty page probe - folio version (kernel >= 5.17)
 *
 * folio_mark_dirty() marks a folio as modified in newer kernels.
 */
int trace_folio_mark_dirty(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DIRTY;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Writeback start probe - page version (kernel < 5.17)
 *
 * clear_page_dirty_for_io() initiates writeback of dirty page.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_clear_page_dirty_for_io(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_START;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback start probe - folio version (kernel >= 5.17)
 *
 * folio_clear_dirty_for_io() starts writeback in newer kernels.
 */
int trace_folio_clear_dirty_for_io(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_START;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Writeback completion probe - page version (kernel < 5.17)
 *
 * test_clear_page_writeback() completes writeback of a page.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_test_clear_page_writeback(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_END;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback completion probe - folio version (kernel >= 5.17)
 *
 * folio_end_writeback() signals writeback completion.
 */
int trace_folio_end_writeback(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_END;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache eviction probe - folio version (kernel >= 5.17)
 *
 * filemap_remove_folio() evicts pages from cache under memory pressure.
 * Process name "kswapd*" indicates background reclaim, others direct reclaim.
 */
int trace_filemap_remove_folio(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  // Detect reclaim context from process name
  // kswapd process indicates background reclaim
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && 
      data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else if (pid > 0) {
    // Non-kswapd process doing eviction likely in direct reclaim
  } else {
  }

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    // Get LRU type from folio/page flags
    // In folio, flags are in the first page (folio is a page array)
    // Try reading flags from folio as if it were a page struct
    unsigned long flags = 0;
    // Cast folio pointer to page pointer to read flags
    struct page *p = (struct page *)folio;
    bpf_probe_read_kernel(&flags, sizeof(flags), &p->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache eviction probe - page version (kernel < 5.17)
 *
 * delete_from_page_cache() for older kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_delete_from_page_cache(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  // Detect reclaim context from process name
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && 
      data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else if (pid > 0) {
  } else {
  }

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    // Get LRU type from page flags
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &page->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache eviction tracepoint - most reliable method
 *
 * Tracepoint probe that works across kernel versions.
 * Particularly reliable for catching drop_caches operations.
 */
TRACEPOINT_PROBE(filemap, mm_filemap_delete_from_page_cache) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  data.inode = args->i_ino;
  data.index = args->index;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.count = 1;  // Single page from tracepoint
  data.size = 0;  // No inode struct access in tracepoint
  data.dev_id = 0;  // No device ID available in tracepoint

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache invalidation probe - invalidate_mapping_pages()
 *
 * Captures explicit page invalidation (not eviction).
 * Count field contains number of pages in the invalidated range.
 */
int trace_invalidate_mapping(struct pt_regs *ctx, struct address_space *mapping,
                             pgoff_t start, pgoff_t end) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_INVALIDATE;
  data.index = start;  // Set before calling populate_cache_metadata
  data.count = (end >= start) ? (u32)(end - start + 1) : 0;  // Inclusive page range
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache invalidation probe - truncate_inode_pages_range()
 *
 * Captures page invalidation during file truncation.
 * Byte offsets are converted to page ranges.
 */
int trace_truncate_pages(struct pt_regs *ctx, struct address_space *mapping,
                         loff_t lstart, loff_t lend) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_INVALIDATE;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  /* Compute page range using PAGE_SHIFT to avoid hardcoded page size and
   * off-by-one issues if lend is inclusive.
   */
  pgoff_t start_index = (pgoff_t)(lstart >> PAGE_SHIFT);
  pgoff_t end_index = (pgoff_t)(lend >> PAGE_SHIFT);

  data.index = start_index;  // starting page index
  if (end_index >= start_index)
    data.count = (u32)(end_index - start_index + 1);
  else
    data.count = 0;

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache drop probe - folio version (kernel >= 5.18)
 *
 * Captures explicit cache drops (e.g., POSIX_FADV_DONTNEED).
 */
int trace_cache_drop_folio(struct pt_regs *ctx, struct address_space *mapping,
                           struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DROP;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);
    
    // Get LRU type from folio/page flags
    unsigned long flags = 0;
    struct page *p = (struct page *)folio;
    bpf_probe_read_kernel(&flags, sizeof(flags), &p->flags);
    if (flags != 0) {
    }
  }

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache drop probe - page version (kernel < 5.17)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_cache_drop_page(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DROP;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    // Get LRU type from page flags
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &page->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache readahead probe - prefetch tracking
 *
 * Captures kernel readahead (prefetch) operations that speculatively
 * load pages into cache. count field contains pages being prefetched.
 */
int trace_do_page_cache_readahead(struct pt_regs *ctx, struct address_space *mapping,
                                   struct file *file, pgoff_t index, unsigned long nr_pages) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_READAHEAD;
  data.index = index;  // Set before calling populate_cache_metadata
  data.count = (u32)nr_pages;  // Number of pages in readahead window
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache reclaim probe - memory pressure tracking
 *
 * shrink_folio_list() is called during memory reclaim.
 * kswapd = background reclaim, other processes = direct reclaim.
 * Direct reclaim indicates memory pressure affecting performance.
 */
int trace_shrink_folio_list(struct pt_regs *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Note: shrink_folio_list operates on a list, so we emit a generic reclaim event
  // Individual folio details would require iterating the list, which is complex in eBPF
  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_RECLAIM;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.inode = 0;  // No specific inode for list-based reclaim
  data.index = 0;
  data.count = 0;  // Would need list iteration to count
  
  // Detect reclaim source: kswapd vs direct reclaim
  // kswapd comm starts with "kswapd"
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else {
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * PAGE FAULT TRACING
 * ============================================================================
 * Page faults occur when accessing memory-mapped files. Major faults
 * require disk I/O, minor faults are served from page cache.
 */

/**
 * @brief File-backed page fault probe
 *
 * filemap_fault() handles page faults for memory-mapped files.
 * Captures the faulting address, file offset, and fault type.
 * Major/minor fault distinction requires return probe analysis.
 *
 * @param ctx  BPF context
 * @param vmf  VM fault context containing fault details
 * @return     0
 */
int trace_filemap_fault_entry(struct pt_regs *ctx, struct vm_fault *vmf) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct pagefault_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  if (vmf) {
    // Get faulting address
    bpf_probe_read_kernel(&data.address, sizeof(data.address), &vmf->address);
    
    // Get page offset (file offset in pages)
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), &vmf->pgoff);
    
    // Determine if this is a write fault
    unsigned int flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &vmf->flags);
    data.fault_type = (flags & 0x01) ? FAULT_WRITE : FAULT_READ;  // FAULT_FLAG_WRITE = 0x01
    
    // Get VMA to access the backing file
    struct vm_area_struct *vma = NULL;
    bpf_probe_read_kernel(&vma, sizeof(vma), &vmf->vma);
    if (vma) {
      struct file *file = NULL;
      bpf_probe_read_kernel(&file, sizeof(file), &vma->vm_file);
      if (file) {
        data.inode = get_file_inode(file);
        
        // Get device ID from superblock
        struct dentry *dentry = NULL;
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
        if (dentry) {
          struct super_block *sb = NULL;
          bpf_probe_read_kernel(&sb, sizeof(sb), &dentry->d_sb);
          if (sb) {
            bpf_probe_read_kernel(&data.dev_id, sizeof(data.dev_id), &sb->s_dev);
          }
        }
      }
    }
  }
  
  // Major/minor fault determination requires kretprobe
  data.major = 0;  // Will be updated by return probe if available

  pagefault_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * IO_URING ASYNC I/O TRACING
 * ============================================================================
 * io_uring is Linux's modern async I/O interface, allowing batched
 * submissions with single syscall overhead.
 */

/**
 * @brief io_uring submission tracepoint
 *
 * Captures io_uring_enter() syscalls that submit I/O batches.
 * len field contains number of operations being submitted.
 * opcode 255 indicates the io_uring_enter syscall itself.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_io_uring_enter) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct iouring_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.fd = args->fd;
  data.len = args->to_submit;
  data.opcode = 255;  // Special value indicating io_uring_enter syscall itself
  data.offset = 0;
  data.result = 0;
  data.latency_ns = 0;

  iouring_events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * DIRECT I/O TRACING
 * ============================================================================
 * Direct I/O bypasses the page cache for applications managing their
 * own caching (databases, etc.).
 */

/**
 * @brief Direct I/O entry probe
 *
 * iomap_dio_rw() handles direct I/O on modern kernels.
 * Stores timestamp for latency calculation on return.
 *
 * @param ctx   BPF context
 * @param iocb  I/O control block
 * @param iter  I/O vector iterator
 * @param ops   DIO operations table
 * @param flags DIO flags
 * @return      0
 */
int trace_dio_entry(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *iter,
                    void *ops, int flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Store start time for latency calculation
  u64 ts = bpf_ktime_get_ns();
  dio_start.update(&pid_tgid, &ts);

  return 0;
}

/**
 * @brief Direct I/O return probe
 *
 * Calculates latency and emits DIO completion event.
 * Return value is bytes transferred (positive) or error (negative).
 */
int trace_dio_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  u64 *start_ts = dio_start.lookup(&pid_tgid);
  if (!start_ts)
    return 0;

  ssize_t ret = PT_REGS_RC(ctx);
  u64 end_ts = bpf_ktime_get_ns();
  u64 latency = end_ts - *start_ts;

  // Emit as a special VFS event with DIO operation type
  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = end_ts;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = (ret >= 0) ? OP_DIO_READ : OP_DIO_WRITE;  // Simplified - actual direction needs more context
  data.size = (ret >= 0) ? (u64)ret : 0;
  data.latency_ns = latency;
  __builtin_memcpy(data.filename, "[direct_io]", 12);

  events.perf_submit(ctx, &data, sizeof(data));

  dio_start.delete(&pid_tgid);
  return 0;
}

/* ============================================================================
 * SPLICE TRACING
 * ============================================================================
 * splice() enables zero-copy data transfer between file descriptors
 * using kernel buffers (pipes) as intermediary.
 */

/**
 * @brief Zero-copy splice probe
 *
 * do_splice() transfers data between file descriptors without
 * copying through userspace. Commonly used for efficient file serving.
 *
 * @param ctx     BPF context
 * @param in      Input file (source)
 * @param off_in  Source offset
 * @param out     Output file (destination)
 * @param off_out Destination offset
 * @param len     Transfer length
 * @param flags   Splice flags (SPLICE_F_*)
 * @return        0
 */
int trace_splice(struct pt_regs *ctx, struct file *in, loff_t *off_in,
                 struct file *out, loff_t *off_out, size_t len, unsigned int flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SPLICE;
  data.size = len;
  data.flags = flags;
  
  // Get source file info if available
  if (in) {
    data.inode = get_file_inode(in);
    get_file_path(in, data.filename, sizeof(data.filename));
    if (off_in) {
      bpf_probe_read_kernel(&data.offset, sizeof(data.offset), off_in);
    }
  } else {
    __builtin_memcpy(data.filename, "[splice]", 9);
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * MEMORY-MAPPED I/O TRACING
 * ============================================================================
 * msync and madvise control how memory-mapped file regions
 * interact with storage and the page cache.
 */

/**
 * @brief msync() system call tracepoint
 *
 * Captures msync() calls that synchronize memory-mapped file
 * regions with storage. MS_SYNC, MS_ASYNC, MS_INVALIDATE flags.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_msync) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = bpf_get_current_pid_tgid();
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MSYNC;
  data.offset = args->start;  // Store address as offset
  data.size = args->len;
  data.flags = args->flags;
  __builtin_memcpy(data.filename, "[msync]", 8);

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief madvise() system call tracepoint
 *
 * Captures madvise() calls that advise kernel about memory usage.
 * MADV_DONTNEED, MADV_WILLNEED, etc. affect page cache behavior.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_madvise) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = bpf_get_current_pid_tgid();
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MADVISE;
  data.offset = args->start;  // Store address as offset
  data.size = args->len_in;
  data.flags = args->behavior;
  __builtin_memcpy(data.filename, "[madvise]", 10);

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * NETWORK I/O PROBES
 * ============================================================================
 * TCP and UDP send/receive operations for correlating network I/O
 * with file system operations.
 */

/**
 * @brief TCP send probe
 *
 * kprobe on tcp_sendmsg() to capture outgoing TCP data.
 *
 * @param ctx  BPF context
 * @param sk   Socket structure
 * @param msg  Message header
 * @param size Data size in bytes
 * @return     0
 */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t size) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct network_data e = {};
  fill_common(&e, 6 /*TCP*/, DIR_SEND, (u32)size);
  if (read_addrs_ports(sk, &e) == 0) {
    net_events.perf_submit(ctx, &e, sizeof(e));
  }
  return 0;
}

/**
 * @brief TCP receive entry probe
 *
 * Stores socket context for correlation with kretprobe.
 * Actual data size is determined in return probe.
 */
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len, int nonblock, int flags,
                        int *addr_len) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  u64 tid = bpf_get_current_pid_tgid();
  tcp_recv_ctx.update(&tid, &sk);
  return 0;
}

/**
 * @brief TCP receive return probe
 *
 * Captures actual received data size from return value.
 * Correlates with entry probe via thread ID.
 */
int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
  int ret = PT_REGS_RC(ctx);
  if (ret <= 0) {
    return 0;
  }
  u64 tid = bpf_get_current_pid_tgid();
  struct sock **skpp = tcp_recv_ctx.lookup(&tid);
  if (!skpp)
    return 0;

  struct network_data e = {};
  fill_common(&e, 6 /*TCP*/, DIR_RECV, (u32)ret);
  if (read_addrs_ports(*skpp, &e) == 0) {
    net_events.perf_submit(ctx, &e, sizeof(e));
  }
  tcp_recv_ctx.delete(&tid);
  return 0;
}

/**
 * @brief UDP send probe
 *
 * kprobe on udp_sendmsg() to capture outgoing UDP datagrams.
 *
 * @param ctx  BPF context
 * @param sk   Socket structure
 * @param msg  Message header
 * @param len  Data length
 * @return     0
 */
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct network_data e = {};
  fill_common(&e, 17 /*UDP*/, DIR_SEND, (u32)len);
  if (read_addrs_ports(sk, &e) == 0) {
    net_events.perf_submit(ctx, &e, sizeof(e));
  }
  return 0;
}

/**
 * @brief UDP receive entry probe
 *
 * Stores socket context for kretprobe correlation.
 */
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len, int flags,
                        int *addr_len) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  u64 tid = bpf_get_current_pid_tgid();
  udp_recv_ctx.update(&tid, &sk);
  return 0;
}

/**
 * @brief UDP receive return probe
 *
 * Captures actual received datagram size from return value.
 */
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
  int ret = PT_REGS_RC(ctx);
  if (ret <= 0) {
    return 0;
  }
  u64 tid = bpf_get_current_pid_tgid();
  struct sock **skpp = udp_recv_ctx.lookup(&tid);
  if (!skpp)
    return 0;

  struct network_data e = {};
  fill_common(&e, 17 /*UDP*/, DIR_RECV, (u32)ret);
  if (read_addrs_ports(*skpp, &e) == 0) {
    net_events.perf_submit(ctx, &e, sizeof(e));
  }
  udp_recv_ctx.delete(&tid);
  return 0;
}
