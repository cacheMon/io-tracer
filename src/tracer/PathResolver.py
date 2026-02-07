"""
PathResolver - Real-time path resolver for inode-to-path mapping.

This module provides the PathResolver class which maintains a cache
of inode-to-path mappings by reading from /proc/<pid>/fd for active processes.
This is useful for resolving file paths when only inode numbers are available
during tracing.

The resolver maintains two caches:
- inode_to_path: Global mapping of inode numbers to file paths
- pid_to_files: Per-process mapping of open file descriptors

Example:
    resolver = PathResolver(cache_timeout=10)
    path = resolver.resolve_path(inode=12345, pid=1234, filename="unknown")
"""

import os
import time
from pathlib import Path


class PathResolver:
    """
    Real-time path resolver that maps inodes to file paths.
    
    This class provides on-the-fly path resolution by reading from
    /proc/<pid>/fd for running processes. It maintains caches to
    avoid repeated filesystem lookups.
    
    The resolver is useful when tracing systems where filenames may
    not be directly available (e.g., when only inode is captured).
    
    Attributes:
        inode_to_path: Dict mapping inode numbers to resolved paths
        pid_to_files: Dict mapping PIDs to their open file mappings
        cache_timeout: Seconds before cache entries expire
        last_update: Dict tracking last update time per PID
    """
    
    def __init__(self, cache_timeout: int = 10):
        """
        Initialize the PathResolver.
        
        Args:
            cache_timeout: Seconds before cache entries expire (default: 10)
        """
        self.inode_to_path = {}
        self.pid_to_files = {}
        self.cache_timeout = cache_timeout
        self.last_update = {}
        
    def update_process_files(self, pid: int) -> dict:
        """
        Update the file mapping for a specific process.
        
        Reads all file descriptors from /proc/<pid>/fd and builds
        a mapping from inode numbers to file paths.
        
        Args:
            pid: Process ID to update
            
        Returns:
            dict: Mapping of inode numbers to file paths for this process
            
        Note:
            This method skips special file descriptors like pipes,
            sockets, and anon_inode files.
        """
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
    
    def resolve_path(self, inode: int, pid: int | None = None, filename: str | None = None) -> str:
        """
        Resolve the full path for an inode.
        
        Attempts to resolve the path in this order:
        1. Check global inode cache
        2. Check process-specific cache if PID provided
        3. Return filename if provided and resolution fails
        
        Args:
            inode: Inode number to resolve
            pid: Optional process ID for process-specific lookup
            filename: Optional fallback filename if resolution fails
            
        Returns:
            str: Resolved path or fallback (filename or "[inode:X]")
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
        """
        Remove old entries from cache to prevent memory bloat.
        
        Removes:
        - Process entries older than cache_timeout * 10 seconds
        - Limits inode cache to 5000 most recent entries
        """
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
