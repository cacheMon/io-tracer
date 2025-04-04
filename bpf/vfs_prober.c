#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>

#define FILENAME_MAX_LEN 256

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
    u64 lba;
    u32 flags;
    enum op_type op;
};

BPF_PERF_OUTPUT(events);

static int get_file_path(struct file *file, char *buf, int size) {
    struct dentry *dentry;
    u64 inode = 0;
    
    if (!file)
        return 0;
        
    dentry = file->f_path.dentry;
    if (!dentry)
        return 0;
    
    if (dentry->d_inode)
        inode = dentry->d_inode->i_ino;
    
    if (dentry->d_name.name)
        bpf_probe_read_kernel(buf, size, dentry->d_name.name);
    else
        __builtin_memcpy(buf, "[unknown]", 10);
        
    return inode;
}

// submit event data
static void submit_event(struct pt_regs *ctx, struct file *file, size_t size, loff_t *pos, enum op_type op) {
    struct data_t data = {};
    u32 pid;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.op = op;
    
    if (file) {
        data.inode = get_file_path(file, data.filename, sizeof(data.filename));
        data.size = size;
        
        if (pos) {
            bpf_probe_read_kernel(&data.lba, sizeof(data.lba), pos);
        }
        
        bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
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
    submit_event(ctx, file, end - start, NULL, OP_FSYNC);
    return 0;
}

// Calls during file close
int trace_fput(struct pt_regs *ctx, struct file *file) {
    if (file) {
        submit_event(ctx, file, 0, NULL, OP_CLOSE);
    }
    return 0;
}