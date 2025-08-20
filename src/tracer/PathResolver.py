import os
import time
from pathlib import Path

class PathResolver:
    """
    Real-time path resolver that can be integrated with IOTracer
    for on-the-fly path resolution during tracing.
    """
    
    def __init__(self, cache_timeout=10):
        self.inode_to_path = {}
        self.pid_to_files = {}
        self.cache_timeout = cache_timeout
        self.last_update = {}
        
    def update_process_files(self, pid):
        """Update the file mapping for a specific process"""
        try:
            current_time = time.time()
            
            # Check if cache is still valid
            if pid in self.last_update:
                if current_time - self.last_update[pid] < self.cache_timeout:
                    return self.pid_to_files.get(pid, {})
            
            files = {}
            fd_dir = f'/proc/{pid}/fd'
            
            if os.path.exists(fd_dir):
                for fd in os.listdir(fd_dir):
                    try:
                        link_path = os.path.join(fd_dir, fd)
                        target = os.readlink(link_path)
                        
                        # Only process regular files
                        if (not target.startswith('pipe:') and 
                            not target.startswith('socket:') and
                            not target.startswith('anon_inode:')):
                            
                            stat_info = os.stat(link_path)
                            inode = stat_info.st_ino
                            files[inode] = target
                            # Update global inode cache
                            self.inode_to_path[inode] = target
                    except:
                        continue
            
            self.pid_to_files[pid] = files
            self.last_update[pid] = current_time
            return files
            
        except:
            return {}
    
    def resolve_path(self, inode, pid=None, filename=None):
        """
        Try to resolve the full path for an inode.
        Returns the path or the original filename if resolution fails.
        """
        
        # Try cache first
        if inode in self.inode_to_path:
            return self.inode_to_path[inode]
        
        # Try to resolve from process
        if pid:
            files = self.update_process_files(pid)
            if inode in files:
                return files[inode]
        
        # If we only have filename, return it
        return filename if filename else f"[inode:{inode}]"
    
    def cleanup_old_cache(self):
        """Remove old entries from cache to prevent memory bloat"""
        current_time = time.time()
        
        # Clean up process cache
        pids_to_remove = []
        for pid, last_time in self.last_update.items():
            if current_time - last_time > self.cache_timeout * 10:
                pids_to_remove.append(pid)
        
        for pid in pids_to_remove:
            del self.pid_to_files[pid]
            del self.last_update[pid]
        
        # Optionally limit inode cache size
        if len(self.inode_to_path) > 10000:
            # Keep only the most recent 5000 entries
            # This is a simple strategy; you might want something more sophisticated
            self.inode_to_path = dict(list(self.inode_to_path.items())[-5000:])