from ..utility.utils import logger, compress_log
from .WriterManager import WriteManager
from datetime import datetime
import gzip
import shutil
import os
import time
import threading

class FilesystemSnapper:
    def __init__(self, wm: WriteManager):
        self.root_path = '/'
        self.visited_real_paths = set()
        self.interrupt = False
        self.wm = wm

    def filesystem_snapshot(self,  max_depth=None):
        def scan_dir(path, current_depth=0):
            if max_depth is not None and current_depth > max_depth:
                return
            
            if self.interrupt:
                return

            try:
                real_path = os.path.realpath(path)
                if real_path in self.visited_real_paths:
                    return
                self.visited_real_paths.add(real_path)
            except:
                return
            
            try:
                items = os.listdir(path)
            except (PermissionError, OSError):
                return
            
            for item in sorted(items):
                item_path = os.path.join(path, item)
                
                try:
                    if os.path.isfile(item_path):
                        file_size = self.get_file_size(item_path)
                        created_time = self.get_created_time(item_path)
                        modification_time = self.get_modification_time(item_path)
                        out = f"{item_path},{file_size},{created_time},{modification_time}"
                        self.wm.append_fs_snap_log(out)
                    elif os.path.isdir(item_path):
                        item_real_path = os.path.realpath(item_path)
                        if item_real_path not in self.visited_real_paths:
                            scan_dir(item_path, current_depth + 1)
                except:
                    continue
        logger('info',"Starting filesystem snapshot...")
        scan_dir(self.root_path)
        logger('info',"Filesystem snapshot completed.")

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
            