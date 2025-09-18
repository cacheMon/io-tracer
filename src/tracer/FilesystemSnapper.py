from ..utility.utils import logger, compress_log
from datetime import datetime
import gzip
import shutil
import os
import time

class FilesystemSnapper:
    def __init__(self, output_dir):
        self.output_fs_snapshot_file = f"{output_dir}/filesystem_paths.csv"
        self.root_path = '/'
        self.all_paths = []
        self.visited_real_paths = set()
        self.interrupt = False

    def filesystem_snapshot(self,  max_depth=None):
        output_file = self.output_fs_snapshot_file
        
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
                        self.all_paths.append(item_path)
                    elif os.path.isdir(item_path):
                        item_real_path = os.path.realpath(item_path)
                        if item_real_path not in self.visited_real_paths:
                            scan_dir(item_path, current_depth + 1)
                except:
                    continue
                    
        logger('info',f"Getting filesystem snapshot, please wait and don't turn off the tracer...")
        scan_dir(self.root_path)
        self.write_snapshot()
        logger('info',f"Snapshot done!")

    def write_snapshot(self):
        logger('info',f"Writing {len(self.all_paths)} paths to {self.output_fs_snapshot_file}...")
        with open(self.output_fs_snapshot_file, 'w') as f:
            for path in sorted(self.all_paths):
                file_size = self.get_file_size(path)
                created_time = self.get_created_time(path)
                modification_time = self.get_modification_time(path)
                out = f"{path},{file_size},{created_time},{modification_time}"
                f.write(out + "\n")
        compress_log(self.output_fs_snapshot_file)

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
            