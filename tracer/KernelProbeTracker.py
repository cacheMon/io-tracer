from bcc import BPF
import sys
from .utils import logger

class KernelProbeTracker:
    def __init__(self, b:BPF):
        self.kprobes = []
        self.b = b

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
        
    def detach_kprobes(self):
        # detach kprobes
        for event, k in self.kprobes:
            try:
                self.b.detach_kprobe(event=event)
                # logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def attach_kprobes(self):
        try:
            self.add_kprobe("vfs_read", "trace_vfs_read")
            self.add_kprobe("vfs_write", "trace_vfs_write")
            self.add_kprobe("vfs_open", "trace_vfs_open")
            self.add_kprobe("vfs_fsync", "trace_vfs_fsync")
            self.add_kprobe("submit_bio","trace_submit_bio")
            if not self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range"):
                logger("info", "vfs_fsync_range not found, using only vfs_fsync")
            self.add_kprobe("__fput", "trace_fput") 
            
            if not self.kprobes:
                logger("error", "no kprobes attached successfully!")
                sys.exit(1)   
        except Exception as e:
            logger("error", f"failed to attach to kernel functions: {e}")
            sys.exit(1)