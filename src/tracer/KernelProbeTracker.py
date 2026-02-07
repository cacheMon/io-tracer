"""
KernelProbeTracker - Manages kernel probe (kprobe) attachment and detachment.

This module provides the KernelProbeTracker class which handles the lifecycle
of kernel probes used to intercept I/O system calls in the Linux kernel.

The tracker supports:
- Kprobes: One-shot probes for function entry
- Kretprobes: Return probes for function exit
- Multiple probe attachment with automatic cleanup
- Kernel version compatibility checks

Example:
    tracker = KernelProbeTracker(bpf_instance)
    tracker.attach_probes()  # Attach all probes
    # ... tracing operations ...
    tracker.detach_kprobes()  # Cleanup when done
"""

import ctypes
import os
from bcc import BPF
import sys
from ..utility.utils import logger


class KernelProbeTracker:
    """
    Manages kernel probe attachment and detachment for eBPF tracing.
    
    This class handles the registration of kprobes and kretprobes on various
    Linux kernel functions related to file I/O operations. It provides:
    - Probe addition (kprobe and kretprobe)
    - Probe detachment (cleanup)
    - Automatic kernel version compatibility detection
    
    Attributes:
        kprobes: List of attached kprobe tuples (event_name, kprobe_object)
        kretprobes: List of attached kretprobe tuples (event_name, kprobe_object)
        b: Reference to the BPF instance
    """
    
    def __init__(self, b: BPF):
        """
        Initialize the KernelProbeTracker.
        
        Args:
            b: BPF instance obtained from BCC library
            
        Initializes empty lists for kprobes and kretprobes,
        stores the BPF reference, and configures the tracer PID
        for excluding the tracer process from traces.
        """
        self.kprobes = []
        self.kretprobes = []
        self.b = b

        tracer_pid = os.getpid()
        config_key = ctypes.c_uint32(0) 
        pid_value = ctypes.c_uint32(tracer_pid)
        self.b["tracer_config"][config_key] = pid_value


    def add_kprobe(self, event: str, kprobe: str) -> bool:
        """
        Attach a kprobe (kernel function entry probe).
        
        Args:
            event: Kernel function name to probe (e.g., "vfs_read")
            kprobe: Name of the BPF function to call when probe triggers
            
        Returns:
            bool: True if attachment succeeded, False otherwise
            
        Raises:
            SystemExit: If probe attachment fails
        """
        try:
            # logger("info", f"Attaching kprobe {event} to {kprobe}")
            k = self.b.attach_kprobe(event=event, fn_name=kprobe)
            self.kprobes.append((event, k))
            return True
        except Exception as e:
            logger("error", f"Failed to attach kprobe {event}: {e}")
            sys.exit(1)
            return False

    def add_kretprobe(self, event: str, kprobe: str) -> bool:
        """
        Attach a kretprobe (kernel function return probe).
        
        Args:
            event: Kernel function name to probe (e.g., "vfs_read")
            kprobe: Name of the BPF function to call when probe triggers
            
        Returns:
            bool: True if attachment succeeded, False otherwise
            
        Raises:
            SystemExit: If probe attachment fails
        """
        try:
            # logger("info", f"Attaching kprobe {event} to {kprobe}")
            k = self.b.attach_kretprobe(event=event, fn_name=kprobe)
            self.kretprobes.append((event, k))
            return True
        except Exception as e:
            logger("error", f"Failed to attach kretprobe {event}: {e}")
            sys.exit(1)
            return False
        
    def detach_kprobes(self):
        """
        Detach all attached kprobes and kretprobes.
        
        Iterates through all registered probes and safely detaches them
        from the kernel. Errors during detachment are logged but do not
        raise exceptions.
        """
        # Detach kprobes
        for event, k in self.kprobes:
            try:
                self.b.detach_kprobe(event=event)
                # logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

        # Detach kretprobes
        for event, k in self.kretprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def detach_kretprobes(self):
        """
        Detach all kretprobes only.
        
        Note: This method currently detaches from kprobes list but uses
        kretprobe detachment. Use detach_kprobes() for complete cleanup.
        """
        # Detach kretprobes (note: iterates over kprobes list, should use kretprobes)
        for event, k in self.kprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def attach_probes(self):
        """
        Attach all kernel probes for I/O tracing.
        
        This method attaches kprobes to various kernel functions related to:
        - Virtual File System (VFS) operations: read, write, open, close, etc.
        - Memory mapping: mmap, munmap
        - Directory operations: readdir, unlink
        - Attribute operations: getattr, setattr
        - Cache operations: hit, miss, dirty, writeback, eviction, etc.
        
        The method performs kernel version compatibility checks and uses
        fallback probes when primary functions are not available.
        
        Raises:
            SystemExit: If no probes can be attached successfully
        """
        try:
            # VFS (Virtual File System) probes
            self.add_kprobe("vfs_read", "trace_vfs_read")
            self.add_kprobe("vfs_write", "trace_vfs_write")
            self.add_kprobe("vfs_open", "trace_vfs_open")
            self.add_kprobe("vfs_fsync", "trace_vfs_fsync")
            self.add_kprobe("ksys_sync", "trace_ksys_sync")
            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
            self.add_kprobe("__fput", "trace_fput")
            
            # Memory mapping probes
            self.add_kprobe("do_mmap", "trace_mmap")
            self.add_kprobe("__vm_munmap", "trace_munmap")
            
            # File attribute probes
            self.add_kprobe("vfs_getattr", "trace_vfs_getattr")
            self.add_kprobe("notify_change", "trace_vfs_setattr") 
            
            # Directory operation probes
            self.add_kprobe("iterate_dir", "trace_readdir")
            self.add_kprobe("vfs_unlink", "trace_vfs_unlink")
            self.add_kprobe("do_truncate", "trace_vfs_truncate")
            
            # Cache Miss probes - kernel version dependent
            if BPF.get_kprobe_functions(b'filemap_add_folio'):
                self.add_kprobe("filemap_add_folio", "trace_filemap_add_folio")
            elif BPF.get_kprobe_functions(b'add_to_page_cache_lru'):
                self.add_kprobe("add_to_page_cache_lru", "trace_miss")
            else:
                logger("warning", "No cache miss probe available")

            # Cache Hit probes - kernel version dependent
            if BPF.get_kprobe_functions(b'folio_mark_accessed'):
                self.add_kprobe("folio_mark_accessed", "trace_folio_mark_accessed")
            elif BPF.get_kprobe_functions(b'mark_page_accessed'):
                self.add_kprobe("mark_page_accessed", "trace_hit")
            else:
                logger("warning", "No cache hit probe available")

            # Dirty Page probes - kernel version dependent
            if BPF.get_kprobe_functions(b'__folio_mark_dirty'):
                self.add_kprobe("__folio_mark_dirty", "trace_folio_mark_dirty")
            elif BPF.get_kprobe_functions(b'account_page_dirtied'):
                self.add_kprobe("account_page_dirtied", "trace_account_page_dirtied")
            else:
                logger("warning", "No dirty page probe available")

            # Writeback Start probes - kernel version dependent
            if BPF.get_kprobe_functions(b'folio_clear_dirty_for_io'):
                self.add_kprobe("folio_clear_dirty_for_io", "trace_folio_clear_dirty_for_io")
            elif BPF.get_kprobe_functions(b'clear_page_dirty_for_io'):
                self.add_kprobe("clear_page_dirty_for_io", "trace_clear_page_dirty_for_io")
            else:
                logger("warning", "No writeback start probe available")

            # Writeback End probes - kernel version dependent
            if BPF.get_kprobe_functions(b'folio_end_writeback'):
                self.add_kprobe("folio_end_writeback", "trace_folio_end_writeback")
            elif BPF.get_kprobe_functions(b'__folio_end_writeback'):
                self.add_kprobe("__folio_end_writeback", "trace_folio_end_writeback")
            elif BPF.get_kprobe_functions(b'test_clear_page_writeback'):
                self.add_kprobe("test_clear_page_writeback", "trace_test_clear_page_writeback")
            else:
                logger("warning", "No writeback end probe available")

            # Eviction probes - kernel version dependent
            if BPF.get_kprobe_functions(b'filemap_remove_folio'):
                self.add_kprobe("filemap_remove_folio", "trace_filemap_remove_folio")
            elif BPF.get_kprobe_functions(b'__filemap_remove_folio'):
                self.add_kprobe("__filemap_remove_folio", "trace_filemap_remove_folio")
            elif BPF.get_kprobe_functions(b'__delete_from_page_cache'):
                self.add_kprobe("__delete_from_page_cache", "trace_delete_from_page_cache")
            else:
                logger("warning", "No eviction probe available")

            # Cache invalidation probes
            if BPF.get_kprobe_functions(b'invalidate_mapping_pages'):
                self.add_kprobe("invalidate_mapping_pages", "trace_invalidate_mapping")
            else:
                logger("warning", "invalidate_mapping_pages not found, invalidation events may be incomplete")

            if BPF.get_kprobe_functions(b'truncate_inode_pages_range'):
                self.add_kprobe("truncate_inode_pages_range", "trace_truncate_pages")
            else:
                logger("warning", "truncate_inode_pages_range not found")

            # Cache drop probes - kernel version dependent
            if BPF.get_kprobe_functions(b'__filemap_remove_folio'):
                # Kernel 5.18+ uses this for explicit page removal
                self.add_kprobe("__filemap_remove_folio", "trace_cache_drop_folio")
            elif BPF.get_kprobe_functions(b'delete_from_page_cache'):
                # Older kernels
                self.add_kprobe("delete_from_page_cache", "trace_cache_drop_page")
            elif BPF.get_kprobe_functions(b'__delete_from_page_cache'):
                # Fallback for some kernel versions
                self.add_kprobe("__delete_from_page_cache", "trace_cache_drop_page")
            else:
                logger("warning", "No cache drop function found, drop events will not be traced")

            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
            self.add_kprobe("__fput", "trace_fput") 
            
            if not self.kprobes:
                logger("error", "no kprobes attached successfully!")
                sys.exit(1)   
        except Exception as e:
            logger("error", f"failed to attach to kernel functions: {e}")
            sys.exit(1)
