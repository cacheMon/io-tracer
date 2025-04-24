#include <linux/ptrace.h>
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

BPF_HASH(file_positions, u64, u64, 1024);

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
    u64 file_inode = 0;
    u64 position = 0;
    u64 next_position = 0;
    u64 lba_value = 0;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.op = op;
    data.lba = 0;  // Default LBA
    
    if (file) {
        file_inode = get_file_path(file, data.filename, sizeof(data.filename));
        data.inode = file_inode;
        data.size = size;
        
        // Try to read position from pos pointer if available
        if (pos) {
            bpf_probe_read_kernel(&position, sizeof(position), pos);
        }
        
        // Try to get current tracked position if we don't have a current position
        if (position == 0) {
            u64 *current_pos = file_positions.lookup(&file_inode);
            if (current_pos) {
                position = *current_pos;
            }
        }
        
        // Calculate LBA from position (minimum LBA is 1 for valid positions)
        lba_value = position / BLOCK_SIZE;
        if (position > 0 && lba_value == 0) {
            lba_value = 1;
        }
        data.lba = lba_value;
        
        // Update position for next operation (for READ and WRITE)
        if (op == OP_READ || op == OP_WRITE) {
            next_position = position + size;
            file_positions.update(&file_inode, &next_position);
        }
        
        // Read flags
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