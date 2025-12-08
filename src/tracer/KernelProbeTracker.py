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
            
            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
            
            self.add_kprobe("__fput", "trace_fput")
            
            
            # self.add_kprobe("blk_mq_start_request", "trace_blk_mq_start_request")
            # self.add_kprobe("blk_account_io_done", "trace_blk_account_io_done")

            if BPF.get_kprobe_functions(b'filemap_add_folio'):
                # logger("info", "Using filemap_add_folio for page cache tracking")
                self.add_kprobe("filemap_add_folio","trace_miss")
            else:
                # logger("info", "Using add_to_page_cache_lru for page cache tracking")
                self.add_kprobe("add_to_page_cache_lru","trace_miss")
            if BPF.get_kprobe_functions(b'folio_mark_accessed'):
                # logger("info", "Using folio_mark_accessed for page access tracking")
                self.add_kprobe("folio_mark_accessed", "trace_hit")
            else:
                # logger("info", "Using mark_page_accessed for page access tracking")
                self.add_kprobe("mark_page_accessed", "trace_hit")

            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
                # logger("info", "vfs_fsync_range not found, using only vfs_fsync")
            self.add_kprobe("__fput", "trace_fput") 
            
            if not self.kprobes:
                # logger("error", "no kprobes attached successfully!")
                sys.exit(1)   
        except Exception as e:
            logger("error", f"failed to attach to kernel functions: {e}")
            sys.exit(1)