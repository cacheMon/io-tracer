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
    def __init__(self, output_dir: str | None, split_threshold: int = 3600 * 24):
        self.current_datetime = datetime.now()
        self.split_threshold = split_threshold

        base_output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis"
        
        timestamp = self.current_datetime.strftime('%Y%m%d_%H%M%S')
        self.output_dir = os.path.join(base_output_dir, f"run_{timestamp}")
        
        self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
        self.output_block_file = f"{self.output_dir}/block/log/block_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
        self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"

        # Create the directory structure (this will work whether it's a new base dir or timestamped subdir)
        os.makedirs(f"{self.output_dir}/vfs/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/block/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache/log", exist_ok=True)

        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()
        
        self.vfs_memory_size = 0
        self.block_memory_size = 0
        self.cache_memory_size = 0
        
        self.cache_max_buffer_size = 200 * 1024 * 1024      
        self.cache_max_events = 50000               
        
        self.vfs_max_buffer_size = 200 * 1024 * 1024     
        self.vfs_max_events = 3000                  
        
        self.block_max_buffer_size = 200 * 1024 * 1024     
        self.block_max_events = 1000               
        
        self.global_max_memory = 1000 * 1024 * 1024       
        self.global_max_events = 5000               
        
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        
        self.cache_sample_rate = 1  # can be increased to reduce cache event volume
        self.cache_event_counter = 0

    def set_cache_sampling(self, sample_rate: int):
        self.cache_sample_rate = sample_rate
        logger("info", f"Cache sampling set to 1:{sample_rate} (every {sample_rate}th event)")

    def get_total_memory_usage(self):
        return self.vfs_memory_size + self.block_memory_size + self.cache_memory_size

    def get_total_events(self):
        return len(self.vfs_buffer) + len(self.block_buffer) + len(self.cache_buffer)

    def should_flush_cache(self):
        return (
            len(self.cache_buffer) >= self.cache_max_events  
            # len(self.cache_buffer) >= self.cache_max_events or 
            # self.cache_memory_size >= self.cache_max_buffer_size
            )

    def should_flush_vfs(self):
        return (
            len(self.vfs_buffer) >= self.vfs_max_events 
            # len(self.vfs_buffer) >= self.vfs_max_events or 
            # self.vfs_memory_size >= self.vfs_max_buffer_size
            )

    def should_flush_block(self):
        return (
            len(self.block_buffer) >= self.block_max_events 
            # len(self.block_buffer) >= self.block_max_events or 
            # self.block_memory_size >= self.block_max_buffer_size
            )

    def should_flush_global(self):
        total_memory = self.get_total_memory_usage()
        total_events = self.get_total_events()
        
        return (total_memory >= self.global_max_memory or 
                total_events >= self.global_max_events)

    def isEventsBigEnough(self, threshold: int = 500):
        
        cache_needs_flush = self.should_flush_cache()
        vfs_needs_flush = self.should_flush_vfs()
        block_needs_flush = self.should_flush_block()
        global_needs_flush = self.should_flush_global()
        
        should_flush = cache_needs_flush or vfs_needs_flush or block_needs_flush or global_needs_flush
        if should_flush:
            total_memory = self.get_total_memory_usage()
            total_events = self.get_total_events()
            
            flush_reasons = []
            if cache_needs_flush:
                flush_reasons.append("cache")
            if vfs_needs_flush:
                flush_reasons.append("vfs")
            if block_needs_flush:
                flush_reasons.append("block")
            if global_needs_flush:
                flush_reasons.append("global")
            
        
        return should_flush

    def append_fs_log(self, log_output: str):
        if isinstance(log_output, str):
            event_size = len(log_output.encode('utf-8')) + 1
            self.vfs_buffer.append(log_output)
            self.vfs_memory_size += event_size
            
            if self.should_flush_vfs():
                self.flush_vfs_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        if isinstance(log_output, str):
            event_size = len(log_output.encode('utf-8')) + 1
            self.block_buffer.append(log_output)
            self.block_memory_size += event_size
            
            if self.should_flush_block():
                self.flush_block_only()
        else:
            logger("error", "Invalid block log output format. Expected a string.")

    def append_cache_log(self, log_output: str):
        if isinstance(log_output, str):
            self.cache_event_counter += 1
            if self.cache_sample_rate > 1 and (self.cache_event_counter % self.cache_sample_rate) != 0:
                return 
            
            event_size = len(log_output.encode('utf-8')) + 1
            self.cache_buffer.append(log_output)
            self.cache_memory_size += event_size
            
            if self.should_flush_cache():
                self.flush_cache_only()
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def flush_cache_only(self):
        print("FLUSHING CACHE!!!")
        if self.cache_buffer:
            if self._cache_handle is None:
                self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
            self.compress_log(self.output_cache_file)
            self.output_cache_file = f"{self.output_dir}/cache/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
            self.cache_memory_size = 0

            self._cache_handle.close()
            self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)


    def flush_vfs_only(self):
        print("FLUSHING FS!!!")
        if self.vfs_buffer:
            if self._vfs_handle is None:
                self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")
            self.compress_log(self.output_vfs_file)
            self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
            self.vfs_memory_size = 0

            self._vfs_handle.close()
            self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)

    def flush_block_only(self):
        print("FLUSHING BLOCK!!!")
        if self.block_buffer:
            if self._block_handle is None:
                self._block_handle = open(self.output_block_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            print("RAFLY GANTENG")
            
            self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
            self.compress_log(self.output_block_file)
            self.output_block_file = f"{self.output_dir}/block/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
            self.block_memory_size = 0

            self._block_handle.close()
            self._block_handle = open(self.output_block_file, 'a', buffering=8192)            

    def force_flush(self):
        print("Compressing All")
        self.compress_log(self.output_block_file)
        self.compress_log(self.output_vfs_file)
        self.compress_log(self.output_cache_file)


    def clear_events(self):
        print("Clear initiated")
        self.vfs_buffer.clear()
        self.block_buffer.clear() 
        self.cache_buffer.clear()
        
        self.vfs_memory_size = 0
        self.block_memory_size = 0
        self.cache_memory_size = 0

    def write_log_header(self):
        try:
            self.write_log_block_direct("timestamp pid tid comm sector nr_sectors operation cpu_id parent_info bio_size\n")
            self.write_log_vfs_direct("timestamp op_name pid comm filename inode size_val flags_str\n")
            self.write_log_cache_direct("timestamp pid comm status\n")
        except IOError as e:
            logger("info", f"Could not open output file: {e}")
            sys.exit(1)

    def write_log_vfs_direct(self, log_output: str):
        if self._vfs_handle is None:
            self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
        self._vfs_handle.write(log_output)
        self._vfs_handle.flush()

    def write_log_block_direct(self, log_output: str):
        if self._block_handle is None:
            self._block_handle = open(self.output_block_file, 'a', buffering=8192)
        self._block_handle.write(log_output)
        self._block_handle.flush()

    def write_log_cache_direct(self, log_output: str):
        if self._cache_handle is None:
            self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
        self._cache_handle.write(log_output)
        self._cache_handle.flush()

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
                self.vfs_memory_size = 0

        def write_block():
            if self.block_buffer:
                if self._block_handle is None:
                    self._block_handle = open(self.output_block_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
                self.block_memory_size = 0

        def write_cache():
            if self.cache_buffer:
                if self._cache_handle is None:
                    self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
                self.cache_memory_size = 0

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

        for thread in threads:
            thread.join()

        self.clear_events()

    def compress_log(self, input_file):
        src = input_file
        dst = input_file + ".gz"

        with open(src, "rb") as f_in:
            with gzip.open(dst, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        print(f"Compressed {src} -> {dst}")
        os.remove(input_file)
        

    def close_handles(self):
        handles = [
            (self._vfs_handle, "VFS"),
            (self._block_handle, "Block"), 
            (self._cache_handle, "Cache")
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

