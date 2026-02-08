#define BPF_NO_KFUNC_PROTO
#include <linux/ptrace.h>

// #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,14,0)
// #define BPF_NO_KFUNC_PROTO
// struct bpf_wq {};
// #endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
struct bpf_timer {};
#endif

#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 0xe1
#endif

#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0xe2
#endif

#ifndef BPF_PSEUDO_FUNC
#define BPF_PSEUDO_FUNC 4
#endif

#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ULL << 3)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
struct bpf_task_work {};
#endif

#include <bcc/proto.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/inet_sock.h>
#include <net/sock.h>

#ifdef __has_include
#if __has_include(<linux/blk-mq.h>)
#include <linux/blk-mq.h>
#endif
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#include <linux/blk-mq.h>
#endif
#endif

#define FILENAME_MAX_LEN 256
#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define TMPFS_MAGIC 0x01021994
#define SOCKFS_MAGIC 0x9fa2
#define DEBUGFS_MAGIC 0x64626720
#define DEVPTS_SUPER_MAGIC 0x1cd1
#define DEVTMPFS_MAGIC 0x74656d70
#define PIPEFS_MAGIC 0x50495045
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define SELINUX_MAGIC 0xf97cff8c
#define NFS_SUPER_MAGIC 0x6969
#define AUTOFS_SUPER_MAGIC 0x0187
#define MQUEUE_MAGIC 0x19800202
#define FUSE_SUPER_MAGIC 0x65735546
#define RAMFS_MAGIC 0x858458f6
#define BINFMTFS_MAGIC 0x42494e4d
#define FUTEXFS_SUPER_MAGIC 0xBAD1DEA
#define EVENTPOLLFS_MAGIC 0x19800202
#define INOTIFYFS_SUPER_MAGIC 0x2BAD1DEA
#define AIO_RING_MAGIC 0x19800202
#define XENFS_SUPER_MAGIC 0xabba1974
#define RPCAUTH_GSSMAGIC 0x67596969
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define TRACEFS_MAGIC 0x74726163
#define OP_LEN 8

enum op_type {
  OP_READ = 1,
  OP_WRITE,
  OP_OPEN,
  OP_CLOSE,
  OP_FSYNC,
  OP_MMAP,
  OP_MUNMAP,
  OP_GETATTR,
  OP_SETATTR,
  OP_CHDIR,
  OP_READDIR,
  OP_UNLINK,
  OP_TRUNCATE,
  OP_SYNC,
  OP_RENAME,
  OP_MKDIR,
  OP_RMDIR,
  OP_LINK,
  OP_SYMLINK,
  OP_FALLOCATE,
  OP_SENDFILE
};

struct data_t {
  u32 pid;
  u64 ts;
  char comm[TASK_COMM_LEN];
  char filename[FILENAME_MAX_LEN];
  u64 inode;
  u64 size;
  u32 flags;
  enum op_type op;
  u64 latency_ns;
};

struct data_dual_t {
  u32 pid;
  u64 ts;
  char comm[TASK_COMM_LEN];
  char filename_old[FILENAME_MAX_LEN];
  char filename_new[FILENAME_MAX_LEN];
  u64 inode_old;
  u64 inode_new;
  u32 flags;
  enum op_type op;
  u64 latency_ns;
};

struct block_event {
  u64 ts;
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 sector;
  char op[OP_LEN];

  u32 tid;
  u32 cpu_id;
  u32 ppid;
  u32 flags;
  u64 bio_size;
  u64 latency_ns;
  u32 dev;        // device number (major:minor) for partition identification
};

enum cache_event_type {
  CACHE_HIT = 0,
  CACHE_MISS = 1,
  CACHE_DIRTY = 2,
  CACHE_WRITEBACK_START = 3,
  CACHE_WRITEBACK_END = 4,
  CACHE_EVICT = 5,
  CACHE_INVALIDATE = 6,
  CACHE_DROP = 7,
  CACHE_READAHEAD = 8,
  CACHE_RECLAIM = 9,
};

struct cache_data {
  u64 ts;
  u32 pid;
  u8 type;
  char comm[TASK_COMM_LEN];
  u64 inode;
  u64 index;
  char filename[FILENAME_MAX_LEN];
  u32 size;
  u64 offset;
  u32 count;
};

enum direction_t { DIR_SEND = 0, DIR_RECV = 1 };

struct network_data {
  u64 ts_ns;
  u32 pid;
  char comm[TASK_COMM_LEN];

  u8 ipver; // 4 or 6
  u8 proto; // 6 = TCP, 17 = UDP
  u8 dir;   // send/recv

  u16 sport;
  u16 dport;

  // IPv4
  u32 saddr_v4;
  u32 daddr_v4;

  // IPv6
  unsigned __int128 saddr_v6;
  unsigned __int128 daddr_v6;

  u32 size_bytes;
};

struct vfs_info {
  u64 start_ts;
  struct file *file;
  size_t size;
  loff_t *pos;
  enum op_type op;
};

BPF_HASH(block_start_times, u64, u64);
BPF_HASH(start, u64, u64);
BPF_HASH(file_positions, u64, u64, 1024);
BPF_HASH(tracer_config, u32, u32, 1);
BPF_HASH(tcp_recv_ctx, u64, struct sock *);
BPF_HASH(udp_recv_ctx, u64, struct sock *);

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(events_dual);
BPF_PERF_OUTPUT(bl_events);
BPF_PERF_OUTPUT(cache_events);

BPF_PERF_OUTPUT(net_events);

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

static u64 get_file_inode(struct file *file) {
  u64 inode = 0;
  if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
    inode = file->f_path.dentry->d_inode->i_ino;
  }
  return inode;
}

static bool is_regular_file(struct file *file) {
  bool is_reg, is_virtual;
  if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode ||
      !file->f_path.dentry->d_sb) {
    return false;
  }
  umode_t mode;
  bpf_probe_read_kernel(&mode, sizeof(mode),
                        &file->f_path.dentry->d_inode->i_mode);
  is_reg = S_ISREG(mode);

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

static u64 get_file_inode_from_dentry(struct dentry *dentry) {
  u64 inode = 0;
  if (dentry && dentry->d_inode) {
    inode = dentry->d_inode->i_ino;
  }
  return inode;
}

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
    __builtin_memcpy(buf, "", 10);
  }

  return 0;
}

/* Helper function to populate cache metadata (size, offset, count)
 * Note: Filename cannot be reliably resolved from inode alone in eBPF
 * because inode->i_dentry is a list requiring complex iteration.
 * The filename field must be populated before calling this helper if needed.
 */
static void populate_cache_metadata(struct cache_data *data, struct inode *inode) {
  if (!inode || !data) {
    return;
  }
  
  // Try to get file size in pages
  loff_t file_size = 0;
  bpf_probe_read_kernel(&file_size, sizeof(file_size), &inode->i_size);
  data->size = (u32)(file_size >> PAGE_SHIFT);  // Convert bytes to number of pages
  
  // Calculate file offset from page index (must be set before calling this)
  data->offset = data->index << PAGE_SHIFT;  // page_index * PAGE_SIZE
  
  // Set count to 1 for single-page operations if not already set
  if (data->count == 0) {
    data->count = 1;
  }
}

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
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_READ;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

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
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_WRITE;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

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
  __builtin_memcpy(data.filename, "", 1);
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

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
  __builtin_memcpy(data.filename, "", 1);
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/* New filesystem operation probes */

int trace_vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
                     struct dentry *old_dentry, struct inode *new_dir,
                     struct dentry *new_dentry) {
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

  struct data_dual_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_RENAME;

  // Get old path and inode
  data.inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data.filename_old, sizeof(data.filename_old));

  // Get new path and inode
  data.inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data.filename_new, sizeof(data.filename_new));

  data.flags = 0;
  data.latency_ns = 0;

  events_dual.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

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

int trace_vfs_link(struct pt_regs *ctx, struct dentry *old_dentry,
                   struct inode *dir, struct dentry *new_dentry) {
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

  struct data_dual_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_LINK;

  // Get old path and inode
  data.inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data.filename_old, sizeof(data.filename_old));

  // Get new path and inode
  data.inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data.filename_new, sizeof(data.filename_new));

  data.flags = 0;
  data.latency_ns = 0;

  events_dual.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_vfs_symlink(struct pt_regs *ctx, struct inode *dir,
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

  struct data_dual_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SYMLINK;
  
  // filename_old is the target of the symlink
  if (oldname) {
    bpf_probe_read_kernel_str(data.filename_old, sizeof(data.filename_old), oldname);
  }
  
  // filename_new is the link name
  get_file_path_from_dentry(dentry, data.filename_new, sizeof(data.filename_new));
  
  data.inode_old = 0;
  data.inode_new = get_file_inode_from_dentry(dentry);
  data.flags = 0;
  data.latency_ns = 0;

  events_dual.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

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
  
  // Protect against overflow in bio_size calculation
  if (args->nr_sector > (1ULL << 52)) {
    event.bio_size = 0;
  } else {
    event.bio_size = ((u64)args->nr_sector) << 9;
  }
  
  event.latency_ns = latency;
  event.flags = 0;  // Reserved for future use
  
  // Capture device number for partition identification
  // dev contains major:minor encoding (major in bits 8-15, minor in bits 0-7 on older kernels,
  // or major in bits 8-15, minor in bits 0-15 with extensions on newer kernels)
  event.dev = args->dev;

  bpf_probe_read_kernel(&event.op, sizeof(event.op), &args->rwbs);

  bl_events.perf_submit(args, &event, sizeof(event));

  block_start_times.delete(&key);
  return 0;
}

static int get_filename(struct dentry *dentry, char *buf) {
  struct qstr d_name = dentry->d_name;
  bpf_probe_read_kernel_str(buf, DNAME_INLINE_LEN, d_name.name);
  return 0;
}

/* Cache Hit - folio version for kernel >= 5.16 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Hit - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Cache Miss - folio version for kernel >= 5.16 */
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
  __builtin_memcpy(data.filename, "", 1);

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Miss - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Dirty Page - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Dirty Page - folio version for newer kernels */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Writeback Start - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Writeback Start - folio version for newer kernels */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Writeback End - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Writeback End - folio version for newer kernels */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Eviction - folio version for newer kernels */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Eviction - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Eviction via tracepoint - most reliable for drop_caches */
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
  data.offset = data.index << 12;  // Calculate offset manually for tracepoint
  data.size = 0;  // No inode struct access in tracepoint
  __builtin_memcpy(data.filename, "", 1);  // Tracepoint doesn't provide inode struct access

  cache_events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/* Cache Invalidation - invalidate_mapping_pages */
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
  __builtin_memcpy(data.filename, "", 1);

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Invalidation - truncate_inode_pages_range */
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
  __builtin_memcpy(data.filename, "", 1);

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Drop - folio version for kernel 5.18+ */
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
  __builtin_memcpy(data.filename, "", 1);

  if (folio) {
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);
  }

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Drop - page version for kernel < 5.17 */
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
  __builtin_memcpy(data.filename, "", 1);

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

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* Cache Readahead - tracks page cache prefetch operations */
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
  __builtin_memcpy(data.filename, "", 1);

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Cache Reclaim - tracks page eviction under memory pressure */
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
  __builtin_memcpy(data.filename, "", 1);

  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* Network probes */

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
