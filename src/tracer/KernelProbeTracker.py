import ctypes
import os
from bcc import BPF
import sys
from ..utility.utils import logger

class KernelProbeTracker:
    def __init__(self, b:BPF):
        self.kprobes = []
        self.kretprobes = []
        self.b = b

        tracer_pid = os.getpid()
        config_key = ctypes.c_uint32(0) 
        pid_value = ctypes.c_uint32(tracer_pid)
        self.b["tracer_config"][config_key] = pid_value


    def add_kprobe(self, event, kprobe):
        try:
            # logger("info", f"Attaching kprobe {event} to {kprobe}")
            k = self.b.attach_kprobe(event=event, fn_name=kprobe)
            self.kprobes.append((event, k))
            return True
        except Exception as e:
            logger("error", f"Failed to attach kprobe {event}: {e}")
            sys.exit(1)
            return False

    def add_kretprobe(self, event, kprobe):
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
        # detach kprobes
        for event, k in self.kprobes:
            try:
                self.b.detach_kprobe(event=event)
                # logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

        for event, k in self.kretprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def detach_kretprobes(self):
        # detach kretprobes
        for event, k in self.kprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def attach_probes(self):
        try:
            self.add_kprobe("vfs_read", "trace_vfs_read")
            
            self.add_kprobe("vfs_write", "trace_vfs_write")
            
            self.add_kprobe("vfs_open", "trace_vfs_open")
            
            self.add_kprobe("vfs_fsync", "trace_vfs_fsync")
            self.add_kprobe("ksys_sync", "trace_ksys_sync")
            
            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
            
            self.add_kprobe("__fput", "trace_fput")
            
            
            self.add_kprobe("do_mmap", "trace_mmap")
            self.add_kprobe("__vm_munmap", "trace_munmap")
            
            self.add_kprobe("vfs_getattr", "trace_vfs_getattr")
            self.add_kprobe("notify_change", "trace_vfs_setattr") 
            
            self.add_kprobe("iterate_dir", "trace_readdir")
            
            self.add_kprobe("vfs_unlink", "trace_vfs_unlink")
            self.add_kprobe("do_truncate", "trace_vfs_truncate")
            
            # Cache Miss probes
            if BPF.get_kprobe_functions(b'filemap_add_folio'):
                self.add_kprobe("filemap_add_folio", "trace_filemap_add_folio")
            elif BPF.get_kprobe_functions(b'add_to_page_cache_lru'):
                self.add_kprobe("add_to_page_cache_lru", "trace_miss")
            else:
                logger("warning", "No cache miss probe available")

            # Cache Hit probes
            if BPF.get_kprobe_functions(b'folio_mark_accessed'):
                self.add_kprobe("folio_mark_accessed", "trace_folio_mark_accessed")
            elif BPF.get_kprobe_functions(b'mark_page_accessed'):
                self.add_kprobe("mark_page_accessed", "trace_hit")
            else:
                logger("warning", "No cache hit probe available")

            # Dirty Page probes
            if BPF.get_kprobe_functions(b'__folio_mark_dirty'):
                self.add_kprobe("__folio_mark_dirty", "trace_folio_mark_dirty")
            elif BPF.get_kprobe_functions(b'account_page_dirtied'):
                self.add_kprobe("account_page_dirtied", "trace_account_page_dirtied")
            else:
                logger("warning", "No dirty page probe available")

            # Writeback Start probes
            if BPF.get_kprobe_functions(b'folio_clear_dirty_for_io'):
                self.add_kprobe("folio_clear_dirty_for_io", "trace_folio_clear_dirty_for_io")
            elif BPF.get_kprobe_functions(b'clear_page_dirty_for_io'):
                self.add_kprobe("clear_page_dirty_for_io", "trace_clear_page_dirty_for_io")
            else:
                logger("warning", "No writeback start probe available")

            # Writeback End probes
            if BPF.get_kprobe_functions(b'folio_end_writeback'):
                self.add_kprobe("folio_end_writeback", "trace_folio_end_writeback")
            elif BPF.get_kprobe_functions(b'__folio_end_writeback'):
                self.add_kprobe("__folio_end_writeback", "trace_folio_end_writeback")
            elif BPF.get_kprobe_functions(b'test_clear_page_writeback'):
                self.add_kprobe("test_clear_page_writeback", "trace_test_clear_page_writeback")
            else:
                logger("warning", "No writeback end probe available")

            # Eviction probes
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