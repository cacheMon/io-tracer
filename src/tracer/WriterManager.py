import os
import sys
import json
import io
from datetime import datetime
from ..utility.utils import logger, create_tar_gz
import threading
from collections import deque
import gzip
import shutil

class WriteManager:
    def __init__(self, output_dir: str ):
        self.current_datetime = datetime.now()

        self.created_files = 0
        self.output_dir = output_dir
        self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_block_file = f"{self.output_dir}/block/log/block_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_process_file = f"{self.output_dir}/process_state/log/process_state_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_fs_snapshot_file = f"{self.output_dir}/filesystem_paths.csv"
        self.output_device_spec = f"{self.output_dir}/device_spec.txt"

        os.makedirs(f"{self.output_dir}/vfs/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/block/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/process_state/log", exist_ok=True)

        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()

        self.process_buffer = deque()
        self.fs_snap_buffer = deque()
        
        self.cache_max_events = 500000
        self.vfs_max_events = 3000
        self.block_max_events = 1000

        self.process_max_events = 2000
        self.fs_snap_max_events = 50000

        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None

        self._process_handle = None
        self._fs_snap_handle = None

        self.cache_sample_rate = 1  # can be increased to reduce cache event volume
        self.cache_event_counter = 0

    def set_cache_sampling(self, sample_rate: int):
        self.cache_sample_rate = sample_rate
        logger("info", f"Cache sampling set to 1:{sample_rate} (every {sample_rate}th event)")

    def should_flush_cache(self):
        return (len(self.cache_buffer) >= self.cache_max_events)

    def should_flush_vfs(self):
        return (len(self.vfs_buffer) >= self.vfs_max_events)

    def should_flush_block(self):
        return (len(self.block_buffer) >= self.block_max_events)

    def should_flush_process(self):
        return (len(self.process_buffer) >= self.process_max_events)

    def should_flush_fssnap(self):
        return (len(self.fs_snap_buffer) >= self.fs_snap_max_events)

    def append_fs_snap_log(self, log_output: str):
        if isinstance(log_output, str):
            if self._fs_snap_handle is None:
                self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
            self.fs_snap_buffer.append(log_output)
            
            if self.should_flush_fssnap():
                self.flush_fssnap_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_fs_log(self, log_output: str):
        if isinstance(log_output, str):
            self.vfs_buffer.append(log_output)
            
            if self.should_flush_vfs():
                self.flush_vfs_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_process_log(self, log_output: str):
        if isinstance(log_output, str):
            self.process_buffer.append(log_output)

            if self.should_flush_process():
                self.flush_process_state_only()
        else:
            logger("error", "Invalid process log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        if isinstance(log_output, str):
            self.block_buffer.append(log_output)
            
            if self.should_flush_block():
                self.flush_block_only()
        else:
            logger("error", "Invalid block log output format. Expected a string.")

    def append_cache_log(self, log_output: str):
        if isinstance(log_output, str):
            self.cache_event_counter += 1
            if self.cache_sample_rate > 1 and (self.cache_event_counter % self.cache_sample_rate) != 0:
                return 
            
            self.cache_buffer.append(log_output)
            
            if self.should_flush_cache():
                self.flush_cache_only()
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def direct_write(self, output_path: str, spec_str: str):
        try:
            with open(f"{self.output_dir}/{output_path}", 'w') as f:
                f.write(spec_str)
        except Exception as e:
            logger("error", f"Error writing device spec to {output_path}: {e}")

    def flush_fssnap_only(self):
        if self.fs_snap_buffer:
            if self._fs_snap_handle is None:
                self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")
            # self.compress_log(self.output_fs_snapshot_file)

            self._fs_snap_handle.close()
            self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)

    def flush_process_state_only(self):
        if self.process_buffer:
            if self._process_handle is None:
                self._process_handle = open(self.output_process_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")
            self.compress_log(self.output_process_file)
            self.output_process_file = f"{self.output_dir}/process_state/log/process_state_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._process_handle.close()
            self._process_handle = open(self.output_process_file, 'a', buffering=8192)

    def flush_cache_only(self):
        if self.cache_buffer:
            if self._cache_handle is None:
                self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
            self.compress_log(self.output_cache_file)
            self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._cache_handle.close()
            self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)


    def flush_vfs_only(self):
        if self.vfs_buffer:
            if self._vfs_handle is None:
                self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")
            self.compress_log(self.output_vfs_file)
            self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._vfs_handle.close()
            self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)

    def flush_block_only(self):
        if self.block_buffer:
            if self._block_handle is None:
                self._block_handle = open(self.output_block_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
            self.compress_log(self.output_block_file)
            self.output_block_file = f"{self.output_dir}/block/log/block_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._block_handle.close()
            self._block_handle = open(self.output_block_file, 'a', buffering=8192)            

    def force_flush(self):
        self.compress_log(self.output_block_file)
        self.compress_log(self.output_vfs_file)
        self.compress_log(self.output_cache_file)
        self.compress_log(self.output_process_file)
        self.compress_log(self.output_fs_snapshot_file)


    def clear_events(self):
        print("Clear initiated")
        self.vfs_buffer.clear()
        self.block_buffer.clear() 
        self.cache_buffer.clear()
        self.process_buffer.clear()
        self.fs_snap_buffer.clear()

    def _write_buffer_to_file(self, buffer, file_handle, buffer_name):
        if not buffer:
            return
            
        try:
            string_buffer = io.StringIO()
            
            while buffer:
                event = buffer.popleft()
                string_buffer.write(event)
                string_buffer.write('\n')
            
            complete_data = string_buffer.getvalue()
            file_handle.write(complete_data)
            file_handle.flush()
            
            string_buffer.close()
            
        except Exception as e:
            logger("error", f"Error writing {buffer_name} buffer: {e}")

    def write_to_disk(self):
        def write_vfs():
            if self.vfs_buffer:
                if self._vfs_handle is None:
                    self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")

        def write_block():
            if self.block_buffer:
                if self._block_handle is None:
                    self._block_handle = open(self.output_block_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")

        def write_cache():
            if self.cache_buffer:
                if self._cache_handle is None:
                    self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")

        def write_process():
            if self.process_buffer:
                if self._process_handle is None:
                    self._process_handle = open(self.output_process_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")

        def write_fssnap():
            if self.fs_snap_buffer:
                if self._fs_snap_handle is None:
                    self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")

        threads = []
        
        if self.vfs_buffer:
            t1 = threading.Thread(target=write_vfs)
            threads.append(t1)
            t1.start()

        if self.block_buffer:
            t2 = threading.Thread(target=write_block)
            threads.append(t2)
            t2.start()

        if self.cache_buffer:
            t3 = threading.Thread(target=write_cache)
            threads.append(t3)
            t3.start()

        if self.process_buffer:
            t4 = threading.Thread(target=write_process)
            threads.append(t4)
            t4.start()

        if self.fs_snap_buffer: 
            t5 = threading.Thread(target=write_fssnap)
            threads.append(t5)
            t5.start()

        for thread in threads:
            thread.join()

        self.clear_events()

    def compress_log(self, input_file):
        src = input_file
        dst = input_file + ".gz"
        self.created_files += 1
        logger('info',f"Files Created: {str(self.created_files)}", True)
        with open(src, "rb") as f_in:
            with gzip.open(dst, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        os.remove(input_file)
        

    def close_handles(self):
        handles = [
            (self._vfs_handle, "VFS"),
            (self._block_handle, "Block"), 
            (self._cache_handle, "Cache"),
            (self._process_handle, "Process State"),
            (self._fs_snap_handle, "Filesystem Snapshot")
        ]
        
        for handle, name in handles:
            if handle:
                try:
                    handle.flush()
                    handle.close()
                    logger("info", f"Closed {name} file handle")
                except Exception as e:
                    logger("error", f"Error closing {name} handle: {e}")
        
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._process_handle = None
        self._fs_snap_handle = None
