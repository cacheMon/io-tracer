#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>

#ifdef __has_include
#  if __has_include(<linux/blk-mq.h>)
#    include <linux/blk-mq.h>
#  endif
#else

# if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
#  include <linux/blk-mq.h>
# endif
#endif

#define FILENAME_MAX_LEN 256
#define PROC_SUPER_MAGIC      0x9fa0      
#define SYSFS_MAGIC           0x62656572  
#define TMPFS_MAGIC           0x01021994  
#define SOCKFS_MAGIC          0x9fa2      
#define DEBUGFS_MAGIC         0x64626720  
#define DEVPTS_SUPER_MAGIC    0x1cd1     
#define DEVTMPFS_MAGIC        0x74656d70  
#define PIPEFS_MAGIC          0x50495045  
#define CGROUP_SUPER_MAGIC    0x27e0eb    
#define SELINUX_MAGIC         0xf97cff8c  
#define NFS_SUPER_MAGIC       0x6969      
#define AUTOFS_SUPER_MAGIC    0x0187      
#define MQUEUE_MAGIC          0x19800202  
#define FUSE_SUPER_MAGIC      0x65735546  
#define RAMFS_MAGIC           0x858458f6  
#define BINFMTFS_MAGIC        0x42494e4d  
#define FUTEXFS_SUPER_MAGIC   0xBAD1DEA   
#define EVENTPOLLFS_MAGIC     0x19800202  
#define INOTIFYFS_SUPER_MAGIC 0x2BAD1DEA  
#define AIO_RING_MAGIC        0x19800202  
#define XENFS_SUPER_MAGIC     0xabba1974 
#define RPCAUTH_GSSMAGIC      0x67596969 
#define OVERLAYFS_SUPER_MAGIC 0x794c7630 
#define TRACEFS_MAGIC         0x74726163 

enum op_type {
    OP_READ = 1,
    OP_WRITE,
    OP_OPEN,
    OP_CLOSE,
    OP_FSYNC
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
};

struct block_event {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 sector;
    u32 nr_sectors;
    u32 op;
    
    u32 tid;                   
    u32 cpu_id;                 
    u32 ppid;                  
    char parent_comm[TASK_COMM_LEN]; 
    u32 flags;               
    u64 bio_size;              
};

struct cache_data {
    u64 ts;          
    u32 pid;
    u8 type;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u64, u64);
BPF_HASH(file_positions, u64, u64, 1024);
BPF_HASH(tracer_config, u32, u32, 1);

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(bl_events);
BPF_PERF_OUTPUT(cache_events);

static u64 get_file_inode(struct file *file) {
    u64 inode = 0;
    if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
        inode = file->f_path.dentry->d_inode->i_ino;
    }
    return inode;
}

static bool is_regular_file(struct file *file) {
    bool is_reg, is_virtual;
    if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode || !file->f_path.dentry->d_sb) {
        return false;
    }
    umode_t mode;
    bpf_probe_read_kernel(&mode, sizeof(mode), &file->f_path.dentry->d_inode->i_mode);
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
        __builtin_memcpy(buf, "[anonymous]", 11);
        return 0;
    }
        
    dentry = file->f_path.dentry;
    if (!dentry) {
        __builtin_memcpy(buf, "[no_dentry]", 12);
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
        if (len <= 0 | first_char == '\0') {
            switch (magic) {
                case 0x9fa0: 
                    __builtin_memcpy(buf, "[procfs]", 9);
                    break;
                case 0x62656572: 
                    __builtin_memcpy(buf, "[sysfs]", 8);
                    break;
                case 0x01021994:
                    __builtin_memcpy(buf, "[tmpfs]", 8);
                    break;
                case 0x9fa2:
                    __builtin_memcpy(buf, "[sockfs]", 9);
                    break;
                case 0x64626720: 
                    __builtin_memcpy(buf, "[debugfs]", 10);
                    break;
                default:
                    __builtin_memcpy(buf, "[unnamed]", 10);
            }
        }
    } else {
        __builtin_memcpy(buf, "[no_name]", 10);
    }
    
    return 0;
}

static int submit_event(struct pt_regs *ctx, struct file *file, size_t size, loff_t *pos, enum op_type op) {
    if (file == NULL) {
        return 0;
    }

    struct data_t data = {};
    u32 pid;
    u64 file_inode = 0;
    u64 position = 0;
    u64 next_position = 0;
    u64 lba_value = 0;
    
    pid = bpf_get_current_pid_tgid() >> 32;
        
    u32 config_key = 0;  // 0 = tracer_pid
    u32 *tracer_pid = tracer_config.lookup(&config_key);
    if (tracer_pid && pid == *tracer_pid) {
        return 0;  // Skip tracing our own process
    }
    
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.op = op;
    
    if (is_regular_file(file)) {
        data.inode = get_file_inode(file);
        data.size = size;
        get_file_path(file, data.filename, sizeof(data.filename));

        
        if (pos) {
            bpf_probe_read_kernel(&position, sizeof(position), pos);
        }
        
        // Read flags
        bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
        events.perf_submit(ctx, &data, sizeof(data));
    }

    
    return 0;
}

int trace_vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos) {
    submit_event(ctx, file, count, pos, OP_READ);
    return 0;
}

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    submit_event(ctx, file, count, pos, OP_WRITE);
    return 0;
}

int trace_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {
    // for open, 0 as size and null as pos
    if (file)
        submit_event(ctx, file, 0, NULL, OP_OPEN);
    return 0;
}

int trace_vfs_fsync(struct pt_regs *ctx, struct file *file, int datasync) {
    submit_event(ctx, file, 0, NULL, OP_FSYNC);
    return 0;
}

int trace_vfs_fsync_range(struct pt_regs *ctx, struct file *file, loff_t start, loff_t end, int datasync) {
    loff_t range_size;
    
    loff_t file_size = 0;
    if (file && file->f_inode) {
        bpf_probe_read_kernel(&file_size, sizeof(file_size), &file->f_inode->i_size);
    }
    
    if (end == LLONG_MAX) {
        range_size = file_size - start;
    } else {
        range_size = end - start;
    }
    
    loff_t pos = start;
    submit_event(ctx, file, range_size, &pos, OP_FSYNC);
    return 0;
}

int trace_fput(struct pt_regs *ctx, struct file *file) {
    if (file) {
        // For close operations, use the file's current position if available
        loff_t *pos = NULL;
        if (file->f_pos) {
            pos = &file->f_pos;
        }
        submit_event(ctx, file, 0, pos, OP_CLOSE);
    }
    return 0;
}

int trace_blk_mq_start_request(struct pt_regs *ctx, struct request *rq) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u32 tracer_pid_key = 0;
    u32 *tracer_pid = tracer_config.lookup(&tracer_pid_key);
    if (tracer_pid && pid == *tracer_pid) {
        return 0;
    }

    if (!rq) {
        return 0;
    }

    struct block_event event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.cpu_id = bpf_get_smp_processor_id();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        event.ppid = task->real_parent->tgid;
        bpf_probe_read_kernel_str(event.parent_comm, sizeof(event.parent_comm), 
                                task->real_parent->comm);
    }
    
    // These fields are more stable at request start time
    bpf_probe_read_kernel(&event.sector, sizeof(event.sector), &rq->__sector);
    
    u32 data_len = 0;
    bpf_probe_read_kernel(&data_len, sizeof(data_len), &rq->__data_len);
    event.bio_size = data_len;
    event.nr_sectors = data_len >> 9;
    
    u32 cmd_flags = 0;
    bpf_probe_read_kernel(&cmd_flags, sizeof(cmd_flags), &rq->cmd_flags);
    event.op = cmd_flags & REQ_OP_MASK;
    event.flags = cmd_flags;
    
    // Validate before submitting
    if (event.bio_size > 0 && event.sector > 0) {
        bl_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}


static int get_filename(struct dentry *dentry, char *buf) {
    struct qstr d_name = dentry->d_name;
    bpf_probe_read_kernel_str(buf, DNAME_INLINE_LEN, d_name.name);
    return 0;
}

int trace_hit(struct pt_regs *ctx, struct page *page) {
    struct cache_data data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 0;
    data.ts = bpf_ktime_get_ns();


    cache_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_miss(struct pt_regs *ctx, struct page *page, struct address_space *mapping, pgoff_t offset, gfp_t gfp_mask) {
    struct cache_data data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 1;

    cache_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}