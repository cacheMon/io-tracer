Below is a **clean implementation plan** that fits the architecture you already described:

* eBPF program: capture events and minimal metadata
* userspace tracer: maintain **`mmap_regions` region cache**
* `MUNMAP` filename recovery uses that cache

We will add support for:

```
mremap
sched_process_exec
sched_process_exit
```

without breaking the existing MMAP/MUNMAP pipeline.

---

# 1. Overview of the Changes

## New probes to add

| Probe                 | Purpose                            |
| --------------------- | ---------------------------------- |
| `sys_mremap` (entry)  | capture old address and size       |
| `sys_mremap` (return) | get new address if moved           |
| `sched_process_exec`  | clear region cache on exec         |
| `sched_process_exit`  | clear region cache on process exit |

---

## New event types 


Used only to update the userspace cache.

```
MREMAP  
PROCESS_EXEC
PROCESS_EXIT
```

---

# 2. Kernel Side Implementation

## 2.1 Add `mremap` probes

Hook:

```
sys_mremap
```

You need:

```
old_address
old_size
new_size
flags
```

Return value gives:

```
new_address
```

---

## Entry probe

Store arguments in staging map.

```c
struct mremap_args {
    u64 old_addr;
    u64 old_len;
    u64 new_len;
    u64 flags;
};
```

Map:

```
BPF_HASH(mremap_staging, u64 pid_tgid, struct mremap_args)
```

Probe:

```c
kprobe/sys_mremap
```

Pseudo:

```
args.old_addr = PT_REGS_PARM1(ctx)
args.old_len  = PT_REGS_PARM2(ctx)
args.new_len  = PT_REGS_PARM3(ctx)
args.flags    = PT_REGS_PARM4(ctx)

store in mremap_staging
```

---

## Return probe

```
kretprobe/sys_mremap
```

Retrieve staging entry.

Return value:

```
long ret = PT_REGS_RC(ctx)
```

If:

```
ret < 0
```

discard.

Otherwise:

```
new_address = ret
```

Emit event containing:

```
PID
old_addr
old_len
new_addr
new_len
flags
```

Then delete staging entry.

---

# 3. Userspace Region Cache Update

Current cache:

```
mmap_regions[(pid, start)] -> {
    end,
    filename
}
```

---

## MREMAP handling logic

When event arrives:

```
(old_addr, old_len) → (new_addr, new_len)
```

### Case 1 — mapping moved

```
old_addr != new_addr
```

Steps:

```
1. locate region containing old_addr
2. remove old region
3. create new region with new address
```

Example:

```
before:
PID 100
0x1000-0x2000 → fileA

after mremap:
0x3000-0x4000 → fileA
```

---

### Case 2 — resize in place

```
old_addr == new_addr
```

Then update region size.

```
region.end = new_addr + new_len
```

---

### Case 3 — region not found

Possible if:

```
mapping existed before tracer started
fork inheritance
```

Simply ignore.

---

# 4. Add Process Lifecycle Hooks

These are **very important** to prevent stale mappings.

---

# 4.1 sched_process_exec

Probe:

```
tracepoint/sched/sched_process_exec
```

Fields available:

```
pid
comm
filename
```

In userspace:

```
delete mmap_regions for PID
```

This is correct because:

```
execve destroys entire address space
```

---

# 4.2 sched_process_exit

Probe:

```
tracepoint/sched/sched_process_exit
```

Userspace action:

```
delete mmap_regions for PID
```

Also good opportunity to clear:

```
inode cache entries owned by PID
fd tracking
```

---

# 5. Userspace Implementation Steps

## Step 1

Add new event handlers:

```
handle_mremap()
handle_process_exec()
handle_process_exit()
```

---

## Step 2

Implement region move logic.

Pseudo:

```
region = find_region(pid, old_addr)

if not region:
    return

delete region

new_start = new_addr
new_end   = new_addr + new_len

insert(pid, new_start, new_end, region.filename)
```

---

## Step 3

Clear cache on lifecycle events.

```
def handle_process_exit(pid):
    delete mmap_regions[pid]

def handle_process_exec(pid):
    delete mmap_regions[pid]
```

---

# 6. Data Structures (No Changes Needed)

Your existing structure works perfectly.

Example:

```
mmap_regions = {
    pid: [
        (start, end, filename),
        ...
    ]
}
```

or

```
(pid,start) → region
```

Either is fine.

---

# 7. CSV Output

add operation types:

```
MREMAP
PROCESS_EXEC
PROCESS_EXIT
```

Example row:

```
2026-03-09 12:33:21.001234,MREMAP,1234,python,,0,,MREMAP_MAYMOVE,0,1234,,,0x7f1234
```


---

# 8. Updated Event Flow

Final pipeline becomes:

```
OPEN
  → inode cache

MMAP
  → mmap_regions

MREMAP
  → update mmap_regions

MUNMAP
  → lookup mmap_regions

EXEC
  → clear mmap_regions[pid]

EXIT
  → clear mmap_regions[pid]
```

---

# 9. Edge Cases Now Covered

| Case                | Fixed?        |
| ------------------- | ------------- |
| fork inheritance    | still limited |
| mremap move         | ✅ fixed       |
| mremap resize       | ✅ fixed       |
| execve address wipe | ✅ fixed       |
| PID reuse           | ✅ fixed       |
| MAP_FIXED overwrite | still rare    |

---

# 10. Implementation Order (recommended)

1️⃣ Add `sched_process_exit` cleanup
2️⃣ Add `sched_process_exec` cleanup
3️⃣ Add `mremap` entry probe
4️⃣ Add `mremap` return probe
5️⃣ Implement userspace region move logic
6️⃣ Add optional CSV event

---

# Final Result

After this change your tracer will correctly handle:

```
mmap
munmap
mremap
exec
exit
```

which covers **~100% of normal VM lifecycle events** seen in real programs.

---
