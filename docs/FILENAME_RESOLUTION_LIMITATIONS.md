# eBPF Filename Resolution Limitations

In the `io-tracer` project, the eBPF prober (e.g., in `src/tracer/prober/prober.c`) only captures the **basename** of files during VFS operations (like `open`, `read`, `write`, `unlink`, etc.) rather than the full absolute path. 

This document explains the technical limitations within eBPF that prevent full path reconstruction directly from the kernel-space probes.

## 1. eBPF Loop and Instruction Limits
To reconstruct a full path from a `struct file *` or `struct dentry *`, the code must manually traverse up the directory tree (`dentry = dentry->d_parent`) in a loop until it reaches the root directory. 

eBPF has strict security rules enforced by the kernel verifier:
- It forbids infinite or unrollable loops.
- It enforces strict bounds on loop iterations and total instruction counts.

A deeply nested directory structure could cause the path reconstruction loop to exceed these limits, causing the kernel to reject the BPF program or the probe to abort silently.

## 2. eBPF Stack Size Limits
eBPF programs are restricted to a tiny stack size of **512 bytes**. Building a full filepath string requires allocating a large buffer (e.g., `PATH_MAX`, which is 4096 bytes on Linux) and doing manual backward string concatenation as you traverse from the file leaf up to the root. Manipulating dynamically sized large strings on such a small stack is extremely prone to stack overflow, leading to guaranteed verifier rejections.

## 3. Restrictions on the `bpf_d_path()` Helper
In Linux 5.10, the kernel introduced a helper function called `bpf_d_path()` specifically designed to safely get the full path without the loop and stack issues. However, the kernel heavily restricts where this helper can be used:
* It is **not allowed** in standard `kprobes` (which this tracer relies on).
* It is restricted to specific tracing program types such as LSM probes or `fentry`/`fexit` programs.
* It is strictly whitelisted to a very small set of kernel functions.

Since `io-tracer` instruments a broad set of VFS functions (like `vfs_read`, `vfs_open`, `vfs_getattr`), the verifier rejects the BPF program if `bpf_d_path()` is used in these hooks.

## 4. Mount Points and Namespace Complexity
Even if loop traversal was unconstrained, a `dentry` structure alone only provides the path relative to its specific mount point. Obtaining the true absolute path as visible to userspace also requires traversing the mount tree (`struct vfsmount`). This adds massive kernel-version-dependent complexity and makes the eBPF program brittle across different Linux kernel versions.

## Alternative and Workaround
The standard industry practice, and the approach used by `io-tracer`, is to:
1. Capture the `inode` number and `basename` in the eBPF kernel space.
2. Defer heavy path resolution to **userspace**. The tracer's userspace component can resolve paths by maintaining its own `inode-to-path` cache, reading `/proc/<pid>/fd/` for open descriptors, or relying on other filesystem metadata tools to map the captured `inodes` to complete paths dynamically as trace data arrives.
