import os
import sys
import json
import io
import gzip
import shutil
import threading
import time
from datetime import datetime
from ..utility.utils import logger, create_tar_gz
from collections import deque
from pathlib import Path

class WriteManager:
    def __init__(self, output_dir: str | None, split_threshold: int = 3600 * 24, 
                 enable_compression: bool = True, compression_interval: int = 300):
        self.current_datetime = datetime.now()
        self.split_threshold = split_threshold
        self.enable_compression = enable_compression
        self.compression_interval = compression_interval
        
        self.file_rotation_count = 0
        self.last_rotation_time = time.time()
        
        self.compression_thread = None
        self.rotation_thread = None
        self.compression_active = False
        self.rotation_active = False
        self.compression_lock = threading.Lock()
        self.files_to_compress = deque()

        base_output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis"
        
        timestamp = self.current_datetime.strftime('%Y%m%d_%H%M%S')
        self.output_dir = os.path.join(base_output_dir, f"run_{timestamp}")
        
        os.makedirs(f"{self.output_dir}/vfs/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/block/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache/log", exist_ok=True)
        os.makedirs(f"{self.output_dir}/compressed", exist_ok=True)
        
        self._update_file_paths()

        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()
        
        self.vfs_memory_size = 0
        self.block_memory_size = 0
        self.cache_memory_size = 0
        
        self.cache_max_buffer_size = 64 * 1024      
        self.cache_max_events = 2000               
        
        self.vfs_max_buffer_size = 512 * 1024      
        self.vfs_max_events = 1000                  
        
        self.block_max_buffer_size = 512 * 1024     
        self.block_max_events = 1000               
        
        self.global_max_memory = 1024 * 1024       
        self.global_max_events = 5000               
        
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        
        self.cache_sample_rate = 1
        self.cache_event_counter = 0
        
        self.stats = {
            'total_events': 0,
            'total_bytes_written': 0,
            'files_compressed': 0,
            'compression_ratio': 0.0
        }
        
        if self.enable_compression:
            self.start_compression_thread()
        self.start_rotation_thread()

    def _update_file_paths(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        suffix = f"_{self.file_rotation_count}" if self.file_rotation_count > 0 else ""
        
        self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{timestamp}{suffix}.log"
        self.output_block_file = f"{self.output_dir}/block/log/block_trace_{timestamp}{suffix}.log"
        self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{timestamp}{suffix}.log"

    def should_rotate_files(self):
        current_time = time.time()
        time_elapsed = current_time - self.last_rotation_time
        
        # Rotate based on time threshold
        if time_elapsed >= self.split_threshold:
            return True
        
        # Rotate based on file size (e.g., 100MB per file)
        max_file_size = 100 * 1024 * 1024  # 100MB
        
        for filepath in [self.output_vfs_file, self.output_block_file, self.output_cache_file]:
            if os.path.exists(filepath) and os.path.getsize(filepath) > max_file_size:
                return True
        
        return False

    def rotate_files(self):
        logger("info", "Rotating trace files...")
        
        self.force_flush()
        
        self.close_handles()
        
        with self.compression_lock:
            if os.path.exists(self.output_vfs_file):
                self.files_to_compress.append(self.output_vfs_file)
            if os.path.exists(self.output_block_file):
                self.files_to_compress.append(self.output_block_file)
            if os.path.exists(self.output_cache_file):
                self.files_to_compress.append(self.output_cache_file)
        
        self.file_rotation_count += 1
        self.last_rotation_time = time.time()
        self._update_file_paths()
        
        self.write_log_header()
        
        logger("info", f"Rotated to new files (rotation #{self.file_rotation_count})")

    def compress_file(self, filepath: str) -> bool:
        try:
            compressed_path = f"{self.output_dir}/compressed/{os.path.basename(filepath)}.gz"
            
            original_size = os.path.getsize(filepath)
            
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            compressed_size = os.path.getsize(compressed_path)
            
            self.stats['files_compressed'] += 1
            compression_ratio = (1 - compressed_size / original_size) * 100
            self.stats['compression_ratio'] = (
                (self.stats['compression_ratio'] * (self.stats['files_compressed'] - 1) + 
                 compression_ratio) / self.stats['files_compressed']
            )
            
            os.remove(filepath)
            
            logger("info", f"Compressed {os.path.basename(filepath)}: "
                         f"{original_size:,} -> {compressed_size:,} bytes "
                         f"({compression_ratio:.1f}% reduction)")
            
            return True
            
        except Exception as e:
            logger("error", f"Failed to compress {filepath}: {e}")
            return False

    def rotation_worker(self):
        logger("info", f"Rotation thread started (check every {min(10, self.split_threshold)}s)")
        
        while self.rotation_active:
            try:
                check_interval = min(10, max(1, self.split_threshold // 10))
                time.sleep(check_interval)
                
                if self.should_rotate_files():
                    self.rotate_files()
                    
            except Exception as e:
                logger("error", f"Rotation thread error: {e}")
                time.sleep(5)
        
        logger("info", "Rotation thread stopped")

    def compression_worker(self):
        logger("info", f"Compression thread started (interval: {self.compression_interval}s)")
        
        while self.compression_active:
            try:
                files_compressed = 0
                with self.compression_lock:
                    while self.files_to_compress and files_compressed < 5:
                        filepath = self.files_to_compress.popleft()
                        if os.path.exists(filepath):
                            self.compress_file(filepath)
                            files_compressed += 1
                
                time.sleep(self.compression_interval)
                    
            except Exception as e:
                logger("error", f"Compression thread error: {e}")
                time.sleep(5)
        
        logger("info", "Compression thread stopped")

    def start_rotation_thread(self):
        if self.rotation_thread is None or not self.rotation_thread.is_alive():
            self.rotation_active = True
            self.rotation_thread = threading.Thread(target=self.rotation_worker)
            self.rotation_thread.daemon = True
            self.rotation_thread.start()

    def stop_rotation_thread(self):
        if self.rotation_thread and self.rotation_active:
            logger("info", "Stopping rotation thread...")
            self.rotation_active = False
            self.rotation_thread.join(timeout=10)

    def start_compression_thread(self):
        if self.compression_thread is None or not self.compression_thread.is_alive():
            self.compression_active = True
            self.compression_thread = threading.Thread(target=self.compression_worker)
            self.compression_thread.daemon = True
            self.compression_thread.start()

    def stop_compression_thread(self):
        if self.compression_thread and self.compression_active:
            logger("info", "Stopping compression thread...")
            self.compression_active = False
            self.compression_thread.join(timeout=10)
            
            # Compress any remaining files
            with self.compression_lock:
                while self.files_to_compress:
                    filepath = self.files_to_compress.popleft()
                    if os.path.exists(filepath):
                        self.compress_file(filepath)

    def set_cache_sampling(self, sample_rate: int):
        self.cache_sample_rate = sample_rate
        logger("info", f"Cache sampling set to 1:{sample_rate}")

    def get_total_memory_usage(self):
        return self.vfs_memory_size + self.block_memory_size + self.cache_memory_size

    def get_total_events(self):
        return len(self.vfs_buffer) + len(self.block_buffer) + len(self.cache_buffer)

    def should_flush_cache(self):
        return (len(self.cache_buffer) >= self.cache_max_events or 
                self.cache_memory_size >= self.cache_max_buffer_size)

    def should_flush_vfs(self):
        return (len(self.vfs_buffer) >= self.vfs_max_events or 
                self.vfs_memory_size >= self.vfs_max_buffer_size)

    def should_flush_block(self):
        return (len(self.block_buffer) >= self.block_max_events or 
                self.block_memory_size >= self.block_max_buffer_size)

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
        
        return cache_needs_flush or vfs_needs_flush or block_needs_flush or global_needs_flush

    def append_fs_log(self, log_output: str):
        if isinstance(log_output, str):
            event_size = len(log_output.encode('utf-8')) + 1
            self.vfs_buffer.append(log_output)
            self.vfs_memory_size += event_size
            self.stats['total_events'] += 1
            
            if self.should_flush_vfs():
                self.flush_vfs_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        if isinstance(log_output, str):
            event_size = len(log_output.encode('utf-8')) + 1
            self.block_buffer.append(log_output)
            self.block_memory_size += event_size
            self.stats['total_events'] += 1
            
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
            self.stats['total_events'] += 1
            
            if self.should_flush_cache():
                self.flush_cache_only()
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def flush_cache_only(self):
        if self.cache_buffer:
            if self._cache_handle is None:
                self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
            
            self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
            self.cache_memory_size = 0

    def flush_vfs_only(self):
        if self.vfs_buffer:
            if self._vfs_handle is None:
                self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
            
            self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")
            self.vfs_memory_size = 0

    def flush_block_only(self):
        if self.block_buffer:
            if self._block_handle is None:
                self._block_handle = open(self.output_block_file, 'a', buffering=8192)
            
            self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
            self.block_memory_size = 0

    def force_flush(self):
        self.write_to_disk()

    def clear_events(self):
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
            bytes_written = 0
            
            while buffer:
                event = buffer.popleft()
                string_buffer.write(event)
                string_buffer.write('\n')
                bytes_written += len(event) + 1
            
            complete_data = string_buffer.getvalue()
            file_handle.write(complete_data)
            file_handle.flush()
            
            self.stats['total_bytes_written'] += bytes_written
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
                except Exception as e:
                    logger("error", f"Error closing {name} handle: {e}")
        
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None

    def cleanup(self):
        """Cleanup method to be called on shutdown."""
        # Stop threads
        if self.enable_compression:
            self.stop_compression_thread()
        self.stop_rotation_thread()
        
        # Final flush and close
        self.force_flush()
        self.close_handles()
        
        # Compress current files if they have content
        if self.enable_compression:
            for filepath in [self.output_vfs_file, self.output_block_file, self.output_cache_file]:
                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    self.compress_file(filepath)
        
        # Print final statistics
        logger("info", f"Trace statistics:")
        logger("info", f"  Total events: {self.stats['total_events']:,}")
        logger("info", f"  Total bytes written: {self.stats['total_bytes_written']:,}")
        logger("info", f"  Files compressed: {self.stats['files_compressed']}")
        if self.stats['files_compressed'] > 0:
            logger("info", f"  Average compression ratio: {self.stats['compression_ratio']:.1f}%")

    def get_output_summary(self):
        """Get a summary of output files for final reporting."""
        summary = {
            'output_dir': self.output_dir,
            'rotations': self.file_rotation_count,
            'compressed_files': [],
            'active_files': []
        }
        
        # List compressed files
        compressed_dir = f"{self.output_dir}/compressed"
        if os.path.exists(compressed_dir):
            summary['compressed_files'] = sorted(os.listdir(compressed_dir))
        
        # List active (uncompressed) files
        for subdir in ['vfs/log', 'block/log', 'cache/log']:
            full_path = f"{self.output_dir}/{subdir}"
            if os.path.exists(full_path):
                for file in os.listdir(full_path):
                    if file.endswith('.log'):
                        summary['active_files'].append(f"{subdir}/{file}")
        
        return summary