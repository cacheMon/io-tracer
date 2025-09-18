from ..utility.utils import logger, compress_log
from .WriterManager import WriteManager
from datetime import datetime
import gzip
import shutil
import os
import time
import threading

class FilesystemSnapper:
    def __init__(self, wm):
        self.root_path = "/"
        self.interrupt = False
        self.wm = wm
        self._visited_inodes = set()
        self._root_dev = os.stat(self.root_path).st_dev

    def filesystem_snapshot(self, max_depth=3):
        def scan_dir(path, depth=0):
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
                                est = entry.stat(follow_symlinks=False)  
                                size = est.st_size
                                ctime = datetime.fromtimestamp(getattr(est, "st_birthtime", est.st_mtime))
                                mtime = datetime.fromtimestamp(est.st_mtime)
                                out = f"{entry.path},{size},{ctime},{mtime}"
                                self.wm.append_fs_snap_log(out)
                            elif entry.is_dir(follow_symlinks=False):
                                scan_dir(entry.path, depth + 1)
                        except Exception:
                            continue
            except Exception:
                return

        logger("info", "Starting filesystem snapshot...")
        scan_dir(self.root_path, 0)
        self.wm.flush_fssnap_only()
        logger("info", "Filesystem snapshot completed.")

    def stop_snapper(self):
        self.interrupt = True

    def get_file_size(self, path):
        try:
            return os.path.getsize(path)
        except (OSError, FileNotFoundError):
            return -1

    def get_created_time(self, path):
        try:
            stat = os.stat(path)    
            try:
                return datetime.fromtimestamp(stat.st_birthtime)
            except AttributeError:
                return datetime.fromtimestamp(stat.st_mtime)
        except (OSError, FileNotFoundError):
            return None

    def get_modification_time(self, path):
        try:
            stat = os.stat(path)    
            return datetime.fromtimestamp(stat.st_mtime)
        except (OSError, FileNotFoundError):
            return None

    def run(self):
        snapper_thread = threading.Thread(target=self.filesystem_snapshot)
        snapper_thread.daemon = True
        snapper_thread.start()
            