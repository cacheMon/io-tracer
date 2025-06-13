#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/blk_types.h>

#define FILENAME_MAX_LEN 256
#define PROC_SUPER_MAGIC      0x9fa0      // procfs
#define SYSFS_MAGIC           0x62656572  // sysfs
#define TMPFS_MAGIC           0x01021994  // tmpfs
#define SOCKFS_MAGIC          0x9fa2      // sockfs
#define DEBUGFS_MAGIC         0x64626720  // debugfs
#define DEVPTS_SUPER_MAGIC    0x1cd1      // devpts
#define DEVTMPFS_MAGIC        0x74656d70  // devtmpfs
#define PIPEFS_MAGIC          0x50495045  // pipefs
#define CGROUP_SUPER_MAGIC    0x27e0eb    // cgroupfs
#define SELINUX_MAGIC         0xf97cff8c  // selinuxfs
#define NFS_SUPER_MAGIC       0x6969      // nfs
#define AUTOFS_SUPER_MAGIC    0x0187      // autofs
#define MQUEUE_MAGIC          0x19800202  // mqueue
#define FUSE_SUPER_MAGIC      0x65735546  // fuse
#define RAMFS_MAGIC           0x858458f6  // ramfs
#define BINFMTFS_MAGIC        0x42494e4d  // binfmt_misc
#define FUTEXFS_SUPER_MAGIC   0xBAD1DEA   // futexfs
#define EVENTPOLLFS_MAGIC     0x19800202  // eventpoll
#define INOTIFYFS_SUPER_MAGIC 0x2BAD1DEA  // inotify
#define AIO_RING_MAGIC        0x19800202  // aio
#define XENFS_SUPER_MAGIC     0xabba1974  // xenfs
#define RPCAUTH_GSSMAGIC      0x67596969  // rpc_pipefs
#define OVERLAYFS_SUPER_MAGIC 0x794c7630  // overlayfs
#define TRACEFS_MAGIC         0x74726163  // tracefs

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

struct bio_data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    // dev_t dev;
    u64 sector;        // Starting sector
    u32 nr_sectors;    // Number of sectors
    u32 rwbs;          // Read/write/discard/flush flags
    // u64 ino;           // Attempt to get inode if possible
    u32 op;            // Operation type
};

BPF_HASH(file_positions, u64, u64, 1024);

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(bl_events);

static u64 get_file_inode(struct file *file) {
    u64 inode = 0;
    if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
        inode = file->f_path.dentry->d_inode->i_ino;
    }
    return inode;
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
    

    
    // Try to detect special filesystem types
    struct super_block *sb = dentry->d_sb;
    unsigned long magic = 0;
    if (sb) {
        bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);
    }
    
    // Check if name is available
    const unsigned char *name_ptr;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
    
    if (name_ptr) {
        // Try to read the name
        bpf_probe_read_kernel_str(buf, size, name_ptr);
        
        // Check if we got anything
        if (buf[0] == '\0') {
            // Check for specific filesystems based on magic number
            switch (magic) {
                case 0x9fa0: // PROCFS_MAGIC
                    __builtin_memcpy(buf, "[procfs]", 9);
                    break;
                case 0x62656572: // SYSFS_MAGIC
                    __builtin_memcpy(buf, "[sysfs]", 8);
                    break;
                case 0x01021994: // TMPFS_MAGIC
                    __builtin_memcpy(buf, "[tmpfs]", 8);
                    break;
                case 0x9fa2: // SOCKFS_MAGIC
                    __builtin_memcpy(buf, "[sockfs]", 9);
                    break;
                case 0x64626720: // DEBUGFS_MAGIC
                    __builtin_memcpy(buf, "[debugfs]", 10);
                    break;
                default:
                    __builtin_memcpy(buf, "[unnamed]", 10);
            }
        }
    } else {
        __builtin_memcpy(buf, "[no_name]", 10);
    }
    
    // Log the filename with error handling (don't use direct pointer access)
    // bpf_trace_printk("Filename: %s, inode: %lu, fs_magic: 0x%lx\n", buf, inode, magic);
    return 0;
}

// submit event data
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
    
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.op = op;
    
    if (file) {
        data.inode = get_file_inode(file);
        get_file_path(file, data.filename, sizeof(data.filename));
        data.size = size;
        
        // Try to read position from pos pointer if available
        if (pos) {
            bpf_probe_read_kernel(&position, sizeof(position), pos);
        }
        
        // bpf_trace_printk("Pos: %d\n",*pos);

        // Try to get current tracked position if we don't have a current position
        if (position == 0) {
            u64 *current_pos = file_positions.lookup(&file_inode);
            if (current_pos) {
                position = *current_pos;
            }
        }
        
        // Update position for next operation (for READ and WRITE)
        if (op == OP_READ || op == OP_WRITE) {
            next_position = position + size;
            file_positions.update(&file_inode, &next_position);
        }
        
        // Read flags
        bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
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
    loff_t pos = start;
    submit_event(ctx, file, end - start, &pos, OP_FSYNC);
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

int trace_submit_bio(struct pt_regs *ctx, struct bio *bio) {
    struct bio_data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    bpf_probe_read_kernel(&data.sector, sizeof(data.sector), &bio->bi_iter.bi_sector);
    data.nr_sectors = bio->bi_iter.bi_size >> 9; 

    data.op = bio->bi_opf & REQ_OP_MASK; 
    
    
    bl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
