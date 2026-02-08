"""
WriterManager - Manages writing trace data to files with buffering and compression.

This module provides the WriteManager class which handles:
- Creating output directory structure
- Buffering trace events for different subsystems
- Writing events to CSV files
- Compressing output files with gzip
- Optionally uploading files to cloud storage

The manager uses adaptive buffering to handle high event rates and
supports multiple output streams (VFS, block, cache, network, etc.).

Example:
    writer = WriteManager(
        output_dir="/path/to/output",
        upload_manager=upload_manager,
        automatic_upload=True
    )
    writer.append_fs_log("event_data")
    writer.force_flush()  # Flush all buffers on shutdown
"""

import os
import sys
import json
import io
from datetime import datetime
import tarfile

from .ObjectStorageManager import ObjectStorageManager
from ..utility.utils import logger, create_tar_gz
import threading
from collections import deque
import gzip
import shutil
import time


class WriteManager:
    """
    Manages writing trace data to disk with buffering and compression.
    
    This class handles all file I/O operations for the tracer, including:
    - Creating and managing output directories
    - Buffering events for different subsystems
    - Flushing buffers to CSV files
    - Compressing output files
    - Optional automatic upload
    
    Attributes:
        output_dir: Base directory for all output files
        upload_manager: ObjectStorageManager for uploads
        automatic_upload: Whether to auto-upload compressed files
        
    Output Files:
        fs/*.csv: File system operation traces
        ds/*.csv: Block device traces
        cache/*.csv: Page cache event traces
        process/*.csv: Process state snapshots
        nw/*.csv: Network operation traces
        filesystem_snapshot/*.csv: Filesystem snapshot
        system_spec/*: System specification files
    """
    
    def __init__(self, output_dir: str, upload_manager: ObjectStorageManager, automatic_upload: bool):
        """
        Initialize the WriteManager.
        
        Args:
            output_dir: Base directory for output files
            upload_manager: ObjectStorageManager for uploads
            automatic_upload: Whether to auto-upload files
        """
        self.current_datetime = datetime.now()

        self.created_files = 0
        self.output_dir = output_dir
        self.output_vfs_file = f"{self.output_dir}/fs/fs_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_block_file = f"{self.output_dir}/ds/ds_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_cache_file = f"{self.output_dir}/cache/cache_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_network_file = f"{self.output_dir}/nw/nw_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_fs_snapshot_file = f"{self.output_dir}/filesystem_snapshot/filesystem_snapshot_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

        # Create output directories
        os.makedirs(f"{self.output_dir}/system_spec", exist_ok=True)
        os.makedirs(f"{self.output_dir}/fs", exist_ok=True)
        os.makedirs(f"{self.output_dir}/ds", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache", exist_ok=True)
        os.makedirs(f"{self.output_dir}/process", exist_ok=True)
        os.makedirs(f"{self.output_dir}/filesystem_snapshot", exist_ok=True)
        os.makedirs(f"{self.output_dir}/nw", exist_ok=True)

        self.upload_manager = upload_manager
        self.automatic_upload = automatic_upload

        # Event buffers for each subsystem
        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()
        self.network_buffer = deque()
        self.process_buffer = deque()
        self.fs_snap_buffer = deque()
        
        # Event rate tracking
        self.event_timestamps = {
            'vfs': deque(maxlen=1000),
            'block': deque(maxlen=1000),
            'cache': deque(maxlen=1000),
            'network': deque(maxlen=1000),
            'fs_state': deque(maxlen=1000),
            'proc_state': deque(maxlen=1000),
        }
        
        # Dynamic thresholds (min, max)
        self.dynamic_limits = {
            'vfs': (8000, 500000),
            'block': (8000, 50000),
            'cache': (20000, 1000000),
            'network': (8000, 200000),
            'fs_state': (8000, 20000),
            'proc_state': (8000, 10000)  # Match new process_max_events threshold
        }
        
        # Start adaptive sizing thread
        self.adaptive_thread = threading.Thread(target=self._adaptive_sizing, daemon=True)
        self.adaptive_thread.start()
        
        # Start periodic flush thread (every 20 minutes)
        self._periodic_flush_active = True
        self.periodic_flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.periodic_flush_thread.start()
        

        # Buffer flush thresholds
        self.cache_max_events = 20000
        self.vfs_max_events = 8000
        self.block_max_events = 8000
        self.network_max_events = 8000
        self.process_max_events = 8000  # Large enough to fit entire hourly snapshot
        self.fs_snap_max_events = 8000

        # File handles for each output
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._network_handle = None
        self._process_handle = None
        self._fs_snap_handle = None

        # Cache sampling configuration
        self.cache_sample_rate = 1  # Can be increased to reduce cache event volume
        self.cache_event_counter = 0

    def _calculate_event_rate(self, event_type: str) -> float:
        """
        Calculate the event rate for a given event type.
        
        Args:
            event_type: Type of events ('vfs', 'block', 'cache', etc.)
            
        Returns:
            float: Events per second, or 0.0 if insufficient data
        """
        timestamps = self.event_timestamps[event_type]
        if len(timestamps) < 2:
            return 0.0
        
        time_span = timestamps[-1] - timestamps[0]
        if time_span <= 0:
            return 0.0
        
        return len(timestamps) / time_span

    def _adaptive_sizing(self):
        """
        Background thread that adjusts buffer thresholds based on event rates.
        
        Monitors event rates for each subsystem and adjusts buffer flush
        thresholds dynamically to handle high-load situations.
        """
        while True:
            time.sleep(10)  
            
            for event_type in ['vfs', 'block', 'cache', 'network','fs_state','proc_state']:
                rate = self._calculate_event_rate(event_type)
                min_limit, max_limit = self.dynamic_limits[event_type]
                
                if rate > 10000:  
                    new_limit = max_limit
                elif rate > 1000: 
                    new_limit = int(min_limit + (max_limit - min_limit) * 0.7)
                elif rate > 100: 
                    new_limit = int(min_limit + (max_limit - min_limit) * 0.4)
                else:  
                    new_limit = min_limit
                
                if event_type == 'vfs':
                    self.vfs_max_events = new_limit
                elif event_type == 'block':
                    self.block_max_events = new_limit
                elif event_type == 'cache':
                    self.cache_max_events = new_limit
                elif event_type == 'network':
                    self.network_max_events = new_limit
                elif event_type == 'fs_state':
                    self.fs_snap_max_events = new_limit
                elif event_type == 'proc_state':
                    self.process_max_events = new_limit

    def _periodic_flush(self):
        """
        Background thread that flushes all buffers every 5 minutes.
        
        This ensures data is written to disk periodically even if buffers
        haven't reached their thresholds, preventing data loss and reducing
        memory usage during long traces.
        """
        while self._periodic_flush_active:
            time.sleep(1200)  # 1200 seconds = 20 minutes
            if self._periodic_flush_active:  # Check again in case stopped during sleep
                try:
                    self.write_to_disk()
                except Exception as e:
                    logger("error", f"Error in periodic flush: {e}")

    def set_cache_sampling(self, sample_rate: int):
        """
        Set the sampling rate for cache events.
        
        Args:
            sample_rate: N where only 1 in N events is recorded (default: 1 = no sampling)
        """
        self.cache_sample_rate = sample_rate
        logger("info", f"Cache sampling set to 1:{sample_rate} (every {sample_rate}th event)")

    # Buffer threshold check methods
    def should_flush_cache(self) -> bool:
        """Check if cache buffer should be flushed."""
        return (len(self.cache_buffer) >= self.cache_max_events)

    def should_flush_vfs(self) -> bool:
        """Check if VFS buffer should be flushed."""
        return (len(self.vfs_buffer) >= self.vfs_max_events)

    def should_flush_block(self) -> bool:
        """Check if block buffer should be flushed."""
        return (len(self.block_buffer) >= self.block_max_events)

    def should_flush_process(self) -> bool:
        """Check if process buffer should be flushed."""
        return (len(self.process_buffer) >= self.process_max_events)

    def should_flush_fssnap(self) -> bool:
        """Check if filesystem snapshot buffer should be flushed."""
        return (len(self.fs_snap_buffer) >= self.fs_snap_max_events)

    def should_flush_network(self) -> bool:
        """Check if network buffer should be flushed."""
        return (len(self.network_buffer) >= self.network_max_events)


    def append_fs_snap_log(self, log_output: str):
        """
        Add a filesystem snapshot log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            if self._fs_snap_handle is None:
                self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
            self.fs_snap_buffer.append(log_output)
            self.event_timestamps['fs_state'].append(time.time())
            
            if self.should_flush_fssnap():
                self.flush_fssnap_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_fs_log(self, log_output: str):
        """
        Add a filesystem VFS log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.vfs_buffer.append(log_output)
            self.event_timestamps['vfs'].append(time.time())
            
            if self.should_flush_vfs():
                self.flush_vfs_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_process_log(self, log_output: str):
        """
        Add a process state log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.process_buffer.append(log_output)
            self.event_timestamps['proc_state'].append(time.time())

            if self.should_flush_process():
                self.flush_process_state_only()
        else:
            logger("error", "Invalid process log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        """
        Add a block device log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.block_buffer.append(log_output)
            self.event_timestamps['block'].append(time.time())
            
            if self.should_flush_block():
                self.flush_block_only()
        else:
            logger("error", "Invalid block log output format. Expected a string.")

    def append_cache_log(self, log_output: str):
        """
        Add a cache event log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.cache_event_counter += 1
            if self.cache_sample_rate > 1 and (self.cache_event_counter % self.cache_sample_rate) != 0:
                return 
            
            self.cache_buffer.append(log_output)
            self.event_timestamps['cache'].append(time.time())
            
            if self.should_flush_cache():
                self.flush_cache_only()
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def append_network_log(self, log_output: str):
        """
        Add a network event log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.network_buffer.append(log_output)
            self.event_timestamps['network'].append(time.time())

            if self.should_flush_network():
                self.flush_network_only()
        else:
            logger("error", "Invalid network log output format. Expected a string.")


    def direct_write(self, output_path: str, spec_str: str):
        """
        Write a system specification file directly.
        
        Args:
            output_path: Filename for the output
            spec_str: Content to write
        """
        try:
            dst = f"{self.output_dir}/system_spec/{output_path}"
            with open(dst, 'w') as f:
                f.write(spec_str)
            if self.automatic_upload:
                self.upload_manager.append_object(dst)
        except Exception as e:
            logger("error", f"Error writing device spec to {output_path}: {e}")

    def flush_fssnap_only(self):
        """Flush filesystem snapshot buffer to file."""
        if self.fs_snap_buffer:
            if self._fs_snap_handle is None:
                self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")
            self.compress_log(self.output_fs_snapshot_file)
            self.output_fs_snapshot_file = f"{self.output_dir}/filesystem_snapshot/filesystem_snapshot_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._fs_snap_handle.close()
            self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)

    def flush_process_state_only(self):
        """Flush process state buffer to file."""
        if self.process_buffer:
            if self._process_handle is None:
                self._process_handle = open(self.output_process_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")
            self.compress_log(self.output_process_file)
            self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._process_handle.close()
            self._process_handle = open(self.output_process_file, 'a', buffering=8192)

    def flush_cache_only(self):
        """Flush cache buffer to file."""
        if self.cache_buffer:
            if self._cache_handle is None:
                self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()

            self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
            self.compress_log(self.output_cache_file)
            self.output_cache_file = f"{self.output_dir}/cache/cache_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._cache_handle.close()
            self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)


    def flush_vfs_only(self):
        """Flush VFS buffer to file."""
        if self.vfs_buffer:
            if self._vfs_handle is None:
                self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")
            self.compress_log(self.output_vfs_file)
            self.output_vfs_file = f"{self.output_dir}/fs/fs_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._vfs_handle.close()
            self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)

    def flush_block_only(self):
        """Flush block buffer to file."""
        if self.block_buffer:
            if self._block_handle is None:
                self._block_handle = open(self.output_block_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
            self.compress_log(self.output_block_file)
            self.output_block_file = f"{self.output_dir}/ds/ds_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._block_handle.close()
            self._block_handle = open(self.output_block_file, 'a', buffering=8192)

    def flush_network_only(self):
        """Flush network buffer to file."""
        if self.network_buffer:
            if self._network_handle is None:
                self._network_handle = open(self.output_network_file, 'a', buffering=8192)
            self.current_datetime = datetime.now()
            
            self._write_buffer_to_file(self.network_buffer, self._network_handle, "Network")
            self.compress_log(self.output_network_file)
            self.output_network_file = f"{self.output_dir}/nw/nw_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

            self._network_handle.close()
            self._network_handle = open(self.output_network_file, 'a', buffering=8192)

    def force_flush(self):
        """Flush all buffers and compress all output files."""
        self.compress_log(self.output_block_file)
        self.compress_log(self.output_vfs_file)
        self.compress_log(self.output_cache_file)
        self.compress_log(self.output_process_file)
        self.compress_log(self.output_fs_snapshot_file)
        self.compress_log(self.output_network_file)
        self.compress_dir(self.output_dir)


    def clear_events(self):
        """Clear all event buffers."""
        print("Clear initiated")
        self.vfs_buffer.clear()
        self.block_buffer.clear() 
        self.cache_buffer.clear()
        self.process_buffer.clear()
        self.fs_snap_buffer.clear()
        self.network_buffer.clear()

    def _write_buffer_to_file(self, buffer, file_handle, buffer_name: str):
        """
        Write buffer contents to a file handle.
        
        Args:
            buffer: Deque containing log entries
            file_handle: Open file handle to write to
            buffer_name: Name for error logging
        """
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
        """Write all buffered data to disk using parallel threads."""
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

        def write_network():
            if self.network_buffer:
                if self._network_handle is None:
                    self._network_handle = open(self.output_network_file, 'a', buffering=8192)
                self._write_buffer_to_file(self.network_buffer, self._network_handle, "Network")

        threads = []
        
        # Start parallel write threads for each buffer
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

        if self.network_buffer:
            t6 = threading.Thread(target=write_network)
            threads.append(t6)
            t6.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        self.clear_events()

    def compress_log(self, input_file: str):
        """
        Compress a log file with gzip and optionally upload.
        
        Args:
            input_file: Path to the file to compress
        """
        try:
            src = input_file
            dst = input_file + ".gz"
            self.created_files += 1
            logger('info', f"Files Created: {str(self.created_files)}", True)
            with open(src, "rb") as f_in:
                with gzip.open(dst, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out) # type: ignore

            if self.automatic_upload:
                self.upload_manager.append_object(dst)
            os.remove(src)
        except Exception as e:
            logger("error", f"Failed compressing log {input_file}")
            
    def compress_dir(self, input_dir: str):
        """
        Compress a directory to tar.gz and optionally upload.
        
        Args:
            input_dir: Path to the directory to compress
        """
        try:
            src = input_dir
            dst = input_dir.rstrip("/").rstrip("\\") + ".tar.gz"

            self.created_files += 1
            logger("info", f"Files Created: {self.created_files}", True)

            with tarfile.open(dst, "w:gz") as tar:
                tar.add(src, arcname=os.path.basename(src))

            if self.automatic_upload:
                self.upload_manager.append_object(dst)

            shutil.rmtree(src)

        except Exception as e:
            logger("error", f"Failed compressing directory {input_dir}")
        

    def close_handles(self):
        """Close all open file handles and stop background threads."""
        # Stop periodic flush thread
        self._periodic_flush_active = False
        
        handles = [
            (self._vfs_handle, "VFS"),
            (self._block_handle, "Block"), 
            (self._cache_handle, "Cache"),
            (self._process_handle, "Process State"),
            (self._fs_snap_handle, "Filesystem Snapshot"),
            (self._network_handle, "Network"),
        ]
        
        for handle, name in handles:
            if handle:
                try:
                    handle.flush()
                    handle.close()
                    # logger("info", f"Closed {name} file handle")
                except Exception as e:
                    logger("error", f"Error closing {name} handle: {e}")
        
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._process_handle = None
        self._fs_snap_handle = None
        self._network_handle = None
