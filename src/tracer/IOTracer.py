#!/usr/bin/python3
"""
IOTracer - Main tracing class for Linux I/O syscall monitoring.

This module contains the IOTracer class which orchestrates all tracing
operations using eBPF/BPF technology. It captures:
- File system operations (VFS calls: read, write, open, close, etc.)
- Block device I/O operations
- Page cache events (hits, misses, dirty pages, etc.)
- Network operations (send/receive)

The tracer uses kernel probes (kprobes) to intercept I/O syscalls and
collects data in real-time, writing it to compressed CSV files.

Usage:
    tracer = IOTracer(output_dir="/path/to/output", bpf_file="path/to/prober.c")
    tracer.trace()
"""

import shutil
import signal
import os
from bcc import BPF
import time
import sys
from pathlib import Path
from datetime import datetime
import socket
import struct

from .ObjectStorageManager import ObjectStorageManager
from ..utility.utils import capture_machine_id, format_csv_row, logger, hash_filename_in_path, inet6_from_event, simple_hash
from .WriterManager import WriteManager
from .FlagMapper import FlagMapper
from .KernelProbeTracker import KernelProbeTracker
from .PollingThread import PollingThread
from .PathResolver import PathResolver
from .snappers.FilesystemSnapper import FilesystemSnapper
from .snappers.ProcessSnapper import ProcessSnapper
from .snappers.SystemSnapper import SystemSnapper


class IOTracer:
    """
    Main class for tracing Linux I/O operations.
    
    IOTracer initializes and manages the entire tracing pipeline, including:
    - BPF program compilation and kernel probe attachment
    - Event collection from perf buffers
    - Snapshot capture for filesystem and process state
    - Data writing and optional automatic upload
    
    Attributes:
        writer: WriteManager instance for handling data output
        fs_snapper: FilesystemSnapper for capturing filesystem state
        process_snapper: ProcessSnapper for capturing process information
        system_snapper: SystemSnapper for capturing system specifications
        flag_mapper: FlagMapper for decoding operation flags
        running: Boolean indicating if tracing is active
        verbose: Boolean enabling verbose output
        anonymous: Boolean enabling data anonymization
    """
    
    def __init__(
            self, 
            output_dir:         str,
            bpf_file:           str,
            automatic_upload:   bool,
            developer_mode:     bool,
            version:            str,
            is_uncompressed:    bool = False,
            anonymous:          bool = False,
            page_cnt:           int = 8,
            verbose:            bool = False,
            duration:           int | None = None,
            cache_sample_rate:  int = 1
        ):
        """
        Initialize the IOTracer.
        
        Args:
            output_dir: Directory path for output files
            bpf_file: Path to the BPF C source file
            automatic_upload: Whether to automatically upload traces
            developer_mode: Enable developer mode with extra logging
            version: Application version string
            is_uncompressed: Whether to skip compression (default: False)
            anonymous: Whether to anonymize process/file names (default: False)
            page_cnt: Number of pages for perf buffer (default: 8)
            verbose: Enable verbose output (default: False)
            duration: Trace duration in seconds (default: None for indefinite)
            cache_sample_rate: Sample rate for cache events (default: 1 = no sampling)
            
        Raises:
            SystemExit: If page count or duration is invalid
            SystemExit: If BPF initialization fails
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(output_dir, "linux_trace" ,capture_machine_id().upper() ,str(timestamp))

        temp_version = version if not developer_mode else f"vdev"
        if developer_mode:
            logger("warning", "Developer mode enabled: extra logs and checks are active.")
        self.upload_manager     = ObjectStorageManager(temp_version)
        self.automatic_upload   = automatic_upload

        # Test connection for automatic upload
        if self.automatic_upload:
            connection = self.upload_manager.test_connection()
            if not connection:
                self.automatic_upload = False


        self.writer             = WriteManager(output_dir, self.upload_manager, automatic_upload)
        self.fs_snapper         = FilesystemSnapper(self.writer, anonymous)
        self.process_snapper    = ProcessSnapper(self.writer, anonymous)
        self.system_snapper     = SystemSnapper(self.writer)
        self.flag_mapper        = FlagMapper()
        self.running            = True
        self.verbose            = verbose
        self.duration           = duration
        self.anonymous          = anonymous
        self.is_uncompressed    = is_uncompressed
        self.path_resolver      = PathResolver()

        if cache_sample_rate > 1:
            self.writer.set_cache_sampling(cache_sample_rate)

        if page_cnt is None or page_cnt <= 0:
            logger("error", f"Invalid page count: {page_cnt}. Page count must be a positive integer.")
            sys.exit(1)
        self.page_cnt = page_cnt

        if duration is not None and duration <= 0:
            logger("error", f"Invalid duration: {duration}. Duration must be a positive integer.")
            sys.exit(1)

        try:
            # Initialize BPF with the provided source file
            self.b = BPF(src_file=bpf_file.encode(), cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined", "-mllvm", "-bpf-stack-size=4096"])
            self.probe_tracker = KernelProbeTracker(self.b)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            print("Your device are incompatible with this version of IO Tracer. Please notify us at io-tracer@googlegroups.com")
            sys.exit(1)

    def _print_event(self, cpu, data, size):        
        """
        Callback for processing file system VFS events from the perf buffer.
        
        This method is called for each VFS (Virtual File System) operation
        captured by the kernel probes.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = event.filename.decode()
            if self.anonymous:
                filename = hash_filename_in_path(Path(filename))
        except UnicodeDecodeError:
            filename = "[decode_error]"
        
        timestamp = datetime.today()
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
            
        inode_val = event.inode if event.inode != 0 else ""
        
        size_val = event.size if event.size is not None else 0
        output = format_csv_row(timestamp, op_name, event.pid, comm, filename, size_val, inode_val)
        self.writer.append_fs_log(output)
        
    def _print_event_dual(self, cpu, data, size):
        """
        Callback for processing dual-path filesystem events from the perf buffer.
        
        This method handles operations with two paths (source and destination),
        such as rename and link operations.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["events_dual"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename_old = event.filename_old.decode()
            filename_new = event.filename_new.decode()
            if self.anonymous:
                filename_old = hash_filename_in_path(Path(filename_old))
                filename_new = hash_filename_in_path(Path(filename_new))
        except UnicodeDecodeError:
            filename_old = "[decode_error]"
            filename_new = "[decode_error]"
        
        timestamp = datetime.today()
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
            
        inode_old = event.inode_old if event.inode_old != 0 else ""
        inode_new = event.inode_new if event.inode_new != 0 else ""
        
        # Format as "old -> new" for the filename column
        dual_filename = f"{filename_old} -> {filename_new}"
        
        # Use inode_old for the inode column
        inode_val = f"{inode_old}" if inode_old else ""
        
        output = format_csv_row(timestamp, op_name, event.pid, comm, dual_filename, 0, inode_val)
        self.writer.append_fs_log(output)
    
    def _print_event_cache(self, cpu, data, size):       
        """
        Callback for processing page cache events from the perf buffer.
        
        Captures cache hits, misses, dirty pages, writebacks, evictions, etc.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["cache_events"].event(data)
        timestamp = datetime.today()
        pid = event.pid
        comm = event.comm.decode('utf-8', errors='replace')
        
        event_types = {
            0: "HIT",
            1: "MISS",
            2: "DIRTY",
            3: "WRITEBACK_START",
            4: "WRITEBACK_END",
            5: "EVICT",
            6: "INVALIDATE",
            7: "DROP",
            8: "READAHEAD",
            9: "RECLAIM"
        }
        event_name = event_types.get(event.type, "UNKNOWN")
        inode = event.inode if event.inode != 0 else ""
        index = event.index if event.index != 0 else ""
        
        # Cache event metadata
        size = event.size if hasattr(event, 'size') else ""
        cpu_id = event.cpu_id if hasattr(event, 'cpu_id') else ""
        dev_id = event.dev_id if hasattr(event, 'dev_id') else ""
        count = event.count if hasattr(event, 'count') else ""

        output = format_csv_row(timestamp, pid, comm, event_name, inode, index, size, cpu_id, dev_id, count)
        self.writer.append_cache_log(output)

    def _print_event_block(self, cpu, data, size):        
        """
        Callback for processing block device I/O events from the perf buffer.
        
        Captures block-level operations including sector locations, sizes,
        and latency information.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["bl_events"].event(data)
        
        timestamp = datetime.today()
        pid = event.pid
        tid = event.tid
        comm = event.comm.decode('utf-8', errors='replace')
        sector = event.sector
        ops_str = event.op.decode('utf-8', errors='replace')
        ops_str = self.flag_mapper.format_block_ops(ops_str)
        latency_ns = event.latency_ns
        latency_ms = latency_ns / 1_000_000.0
        cpu_id = event.cpu_id
        ppid = event.ppid
        bio_size = event.bio_size
        
        # Decode device number (dev_t) into major:minor for partition identification
        # dev_t encoding: major in bits 8-19, minor in bits 0-19 (on most modern kernels)
        dev = event.dev
        major = (dev >> 20) & 0xfff if dev > 0 else 0
        minor = dev & 0xfffff if dev > 0 else 0
        dev_str = f"{major}:{minor}"
        
        output = format_csv_row(timestamp, pid, comm, sector, ops_str, bio_size, latency_ms, tid, cpu_id, ppid, dev_str)


        if sector == 0 and bio_size == 0:
            if self.verbose:
                print("="*50)
                print("Warning: LBA 0 detected in block trace")
                print(output)
                print("="*50)

        self.writer.append_block_log(output)

    def _print_event_net(self, cpu, data, size):
        """
        Callback for processing network I/O events from the perf buffer.
        
        Captures send and receive operations with source/destination
        addresses and port numbers.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        e = self.b["net_events"].event(data)
        ts = datetime.today()
        pid = e.pid
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        size_bytes = e.size_bytes
        ty = "send" if e.dir == 0 else "receive"

        # Handle IPv4 addresses
        if e.ipver == 4:
            s_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", e.saddr_v4))
            d_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", e.daddr_v4))
        # Handle IPv6 addresses
        elif e.ipver == 6:
            s_addr = inet6_from_event(e.saddr_v6)
            d_addr = inet6_from_event(e.daddr_v6)
        else:
            s_addr = d_addr = "unknown"


        output = format_csv_row(
            ts.strftime("%Y-%m-%d %H:%M:%S.%f"),
            str(pid),
            comm,
            s_addr,
            d_addr,
            str(e.sport),
            str(e.dport),
            str(size_bytes),
            ty,
        )
        self.writer.append_network_log(output)


    def _cleanup(self, signum, frame):
        """
        Signal handler for graceful shutdown.
        
        Stops all tracing, flushes buffers, closes file handles,
        and optionally cleans up for upload.
        
        Args:
            signum: Signal number that triggered the handler
            frame: Current stack frame
        """
        self.running = False
    
        # Detach all kernel probes
        self.probe_tracker.detach_kprobes()
        
        logger("info", "Performing final flush...")
        self.fs_snapper.stop_snapper()
        self.process_snapper.stop_snapper()
        self.writer.write_to_disk()
        
        self.writer.close_handles()

        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self, lost):
        """
        Callback for handling lost events in the perf buffer.
        
        Args:
            lost: Number of events that were lost
        """
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def trace(self):
        """
        Main method to start tracing operations.
        
        This method:
        1. Attaches all kernel probes
        2. Starts the upload worker if enabled
        3. Captures initial system/process/filesystem snapshots
        4. Opens perf buffers for all event types
        5. Runs the polling loop until duration expires or interrupted
        
        The trace runs indefinitely if no duration is specified,
        or for the specified number of seconds otherwise.
        """
        self.probe_tracker.attach_probes()
        if self.automatic_upload:
            self.upload_manager.start_worker()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO Tracer is running")
        logger("info", "Press Ctrl+C to exit")
        
        # Capture initial snapshots
        self.system_snapper.capture_spec_snapshot()
        self.fs_snapper.run()
        self.process_snapper.run()

        if self.writer.cache_sample_rate > 1:
            logger("info", f"Cache sampling enabled: 1:{self.writer.cache_sample_rate}")

        # Open perf buffers for each event type
        self.b["events"].open_perf_buffer(
            self._print_event, 
            page_cnt=self.page_cnt, 
            lost_cb=self._lost_cb
        )

        self.b["events_dual"].open_perf_buffer(
            self._print_event_dual,
            page_cnt=self.page_cnt,
            lost_cb=self._lost_cb
        )

        self.b["bl_events"].open_perf_buffer(
            self._print_event_block, 
            page_cnt=self.page_cnt, 
            lost_cb=self._lost_cb
        )

        self.b["cache_events"].open_perf_buffer(
            self._print_event_cache, 
            page_cnt=self.page_cnt, 
            lost_cb=self._lost_cb
        )

        self.b["net_events"].open_perf_buffer(
            self._print_event_net,
            page_cnt=self.page_cnt,
            lost_cb=self._lost_cb
        )

        start = time.time()
        if self.duration is not None:
            duration_target = self.duration
            end_time = start + duration_target
            logger("info", f"Tracing for {duration_target} seconds...")
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")

        # Start the polling thread for perf buffer
        self.polling_thread = PollingThread(self.b, True)
        self.polling_thread.create_thread()

        try:
            if self.duration is not None:
                remaining = duration_target # type: ignore
                while remaining > 0 and self.running:
                    sleep_time = min(0.1, remaining)
                    time.sleep(sleep_time)
                    
                    current = time.time()
                    remaining = end_time - current # type: ignore
                    
                    if self.verbose and int(current) % 10 == 0 and int(current) > int(current - sleep_time):
                        elapsed = current - start
                        logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s") # type: ignore
                        
                self._cleanup(None, None)
            else:
                # Run indefinitely until Ctrl+C
                while self.running:
                    time.sleep(0.1)
                    
                    if self.verbose:
                        current = time.time()
                        if int(current) % 30 == 0:  # Every 30 seconds
                            elapsed = current - start
                            logger("info", f"Runtime: {elapsed:.1f}s")
                            
            self.running = False
            
        except KeyboardInterrupt:
            logger("info", "Keyboard interrupt received")
            self.running = False
        except Exception as e:
            logger("error", f"Main loop error: {e}")
        finally:
            self.polling_thread.polling_active = False
            time.sleep(0.2)
            
            if self.verbose:
                actual_duration = time.time() - start
                logger("info", f"Trace completed after {actual_duration:.2f} seconds")
            
            print()
            logger("info", "Trace stopped")
            logger("info", "Please wait. Compressing trace output...")

            self.writer.force_flush()

            if self.automatic_upload:
                self.upload_manager.stop_worker(False)
                try:
                    os.removedirs(self.writer.output_dir)
                except OSError:
                    pass

            
            logger("info", "Cleanup complete. Exited successfully.")
