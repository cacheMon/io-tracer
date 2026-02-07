"""
FilesystemSnapper - Captures filesystem snapshots during tracing.

This module provides the FilesystemSnapper class which walks the filesystem
hierarchy and records information about files at trace time. This provides
context for understanding which files existed during the trace.

The snapper can operate in two modes:
- Normal: Records actual file paths
- Anonymous: Records hashed/anonymized paths

Example:
    snapper = FilesystemSnapper(writer_manager=wm, anonymous=False)
    snapper.run()  # Start snapshot in background thread
    snapper.stop_snapper()  # Stop the snapper
"""

import random
from ...utility.utils import format_csv_row, logger, compress_log, hash_rel_path, hash_filename_in_path
from ..WriterManager import WriteManager
from pathlib import Path
from datetime import datetime
import gzip
import shutil
import os
import time
import threading


class FilesystemSnapper:
    """
    Captures filesystem snapshots for trace context.
    
    This class traverses the filesystem tree and records information
    about files, including paths, sizes, and timestamps. This data
    provides context for understanding the system state during tracing.
    
    Attributes:
        anonymous: Whether to anonymize file paths
        root_path: Root directory to scan (default: "/")
        interrupt: Flag to stop the snapshot thread
        wm: WriteManager for outputting data
        _visited_inodes: Set of visited inode keys to avoid duplicates
        _root_dev: Device ID of root filesystem
        
    Example:
        snapper = FilesystemSnapper(wm, anonymous=True)
        snapper.run()
        # ... later ...
        snapper.stop_snapper()
    """
    
    def __init__(self, wm: WriteManager, anonymous: bool = False):
        """
        Initialize the FilesystemSnapper.
        
        Args:
            wm: WriteManager for outputting snapshot data
            anonymous: Whether to hash file paths (default: False)
        """
        self.anonymous = anonymous
        self.root_path = "/"
        self.interrupt = False
        self.wm = wm
        self._visited_inodes = set()
        self._root_dev = os.stat(self.root_path).st_dev

    def filesystem_snapshot(self, max_depth: int = 3):
        """
        Perform a filesystem snapshot by walking the directory tree.
        
        Recursively scans directories up to max_depth, recording information
        about each file found. Skips special filesystems and already-visited
        inodes to avoid duplicates.
        
        Args:
            max_depth: Maximum directory depth to traverse (default: 3)
        """
        def scan_dir(path: str, depth: int = 0):
            """Inner function for recursive directory scanning."""
            time.sleep(random.uniform(.2, .5))  
            if self.interrupt or (max_depth is not None and depth > max_depth):
                return
            try:
                st = os.stat(path, follow_symlinks=False)
            except Exception:
                return

            if st.st_dev != self._root_dev:
                return

            key = (st.st_dev, st.st_ino)
            if key in self._visited_inodes:
                return
            self._visited_inodes.add(key)

            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if self.interrupt:
                            return
                        try:
                            if entry.is_file(follow_symlinks=False):
                                if self.anonymous:
                                    est = entry.stat(follow_symlinks=False)  
                                    size = est.st_size
                                    ctime = datetime.fromtimestamp(getattr(est, "st_birthtime", est.st_mtime))
                                    mtime = datetime.fromtimestamp(est.st_mtime)

                                    rel = Path(os.path.relpath(entry.path, start=self.root_path))
                                    hashed_rel = hash_rel_path(rel, keep_ext=True, length=12)
                                    hashed_path = os.path.join(os.sep, str(hashed_rel))
                                    hashed_path = hash_filename_in_path(Path(hashed_path))
                                    out = format_csv_row(hashed_path, size, ctime, mtime)
                                    self.wm.append_fs_snap_log(out)
                                else:
                                    est = entry.stat(follow_symlinks=False)
                                    size = est.st_size
                                    path = hash_filename_in_path(Path(entry.path))
                                    ctime = datetime.fromtimestamp(getattr(est, "st_birthtime", est.st_mtime))
                                    mtime = datetime.fromtimestamp(est.st_mtime)
                                    out = format_csv_row(path, size, ctime, mtime)
                                    self.wm.append_fs_snap_log(out)
                            elif entry.is_dir(follow_symlinks=False):
                                scan_dir(entry.path, depth + 1)
                        except Exception:
                            continue
            except Exception:
                return

        # logger("info", "Starting filesystem snapshot...")
        scan_dir(self.root_path, 0)
        self.wm.flush_fssnap_only()
        # logger("info", "Filesystem snapshot completed.")

    def stop_snapper(self):
        """Signal the snapshot thread to stop."""
        self.interrupt = True

    def get_file_size(self, path: str) -> int:
        """
        Get the size of a file.
        
        Args:
            path: Path to the file
            
        Returns:
            int: File size in bytes, or -1 if file cannot be accessed
        """
        try:
            return os.path.getsize(path)
        except (OSError, FileNotFoundError):
            return -1

    def run(self):
        """Start the snapshot in a background daemon thread."""
        snapper_thread = threading.Thread(target=self.filesystem_snapshot)
        snapper_thread.daemon = True
        snapper_thread.start()
