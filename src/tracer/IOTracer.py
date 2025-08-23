#!/usr/bin/python3

import shutil
import signal
from bcc import BPF
import time
import sys
import os
from ..utility.utils import logger, create_tar_gz
from .WriterManager import WriteManager
from .FlagMapper import FlagMapper
from .KernelProbeTracker import KernelProbeTracker
from .PollingThread import PollingThread
from .PathResolver import PathResolver

class IOTracer:
    def __init__(
            self, 
            output_dir:         str,
            bpf_file:           str,
            split_threshold:    int,
            is_uncompressed:    bool = False,
            anonymous:          bool = False,
            page_cnt:           int = 8,
            verbose:            bool = False,
            duration:           int | None = None,
            cache_sample_rate:  int = 1,
            enable_compression: bool = True,
            compression_interval: int = 300,
            compression_level:  int = 6
        ):
        
        # Initialize WriteManager with compression settings
        self.writer = WriteManager(
            output_dir, 
            split_threshold,
            enable_compression=enable_compression,
            compression_interval=compression_interval
        )
        
        self.flag_mapper        = FlagMapper()
        self.running            = True
        self.verbose            = verbose
        self.duration           = duration
        self.anonymous          = anonymous
        self.is_uncompressed    = is_uncompressed
        self.path_resolver      = PathResolver()
        self.enable_compression = enable_compression
        self.compression_level  = compression_level

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
            self.b = BPF(src_file=bpf_file.encode(), cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined"])
            self.probe_tracker = KernelProbeTracker(self.b)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            sys.exit(1)
        
        # Log compression settings
        if enable_compression:
            logger("info", f"Periodic compression enabled (interval: {compression_interval}s, level: {compression_level})")
            logger("info", f"File rotation threshold: {split_threshold}s")

    def _print_event(self, cpu, data, size):        
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = "[anonymous file]" if self.anonymous else event.filename.decode()
        except UnicodeDecodeError:
            filename = "[decode_error]"
        
        flags_str = self.flag_mapper.format_fs_flags(event.flags)
        timestamp = event.ts
        
        try:
            comm = "[anonymous process]" if self.anonymous else event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        output = f"{timestamp} {op_name} {event.pid} {comm.replace(' ','_')} {filename.replace(' ','_')} {event.inode} {size_val} {flags_str}"
        
        self.writer.append_fs_log(output)
        
    def _print_event_cache(self, cpu, data, size):       
        event = self.b["cache_events"].event(data)
        timestamp = event.ts
        pid = event.pid
        comm = "[anonymous process]" if self.anonymous else event.comm.decode('utf-8', errors='replace')
        hit = "HIT" if event.type == 0 else "MISS"

        output = f"{timestamp} {pid} {comm.replace(' ','_')} {hit}"
        
        self.writer.append_cache_log(output)

    def _print_event_block(self, cpu, data, size):        
        event = self.b["bl_events"].event(data)
        
        timestamp = event.ts
        pid = event.pid
        tid = event.tid
        comm = "[anonymous process]" if self.anonymous else event.comm.decode('utf-8', errors='replace')
        sector = event.sector
        nr_sectors = event.nr_sectors
        ops_str = self.flag_mapper.format_block_operation(event.op)
        cpu_id = event.cpu_id
        ppid = event.ppid
        parent_comm = "[anonymous process]" if self.anonymous else event.parent_comm.decode('utf-8', errors='replace')
        bio_size = event.bio_size
            
        output = (f"{timestamp} {pid} {tid} {comm.replace(' ','_')} {sector} "
                f"{nr_sectors} {ops_str} "
                f"cpu:{cpu_id} ppid:{ppid}({parent_comm}) "
                f"{bio_size}")

        if (sector == 0 and nr_sectors == 0) or (sector == '0' and nr_sectors == '0'):
            if self.verbose:
                print("="*50)
                print("Warning: LBA 0 detected in block trace")
                print(output)
                print("="*50)

        self.writer.append_block_log(output)

    def _cleanup(self, signum, frame):
        self.running = False
    
        self.probe_tracker.detach_kprobes()
        
        logger("info", "Performing cleanup...")
        self.writer.cleanup()  # Use the new cleanup method

        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self, lost):
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def _print_progress(self, start_time, duration_target=None):
        current = time.time()
        elapsed = current - start_time
        
        if duration_target:
            remaining = max(0, duration_target - elapsed)
            progress_pct = min(100, (elapsed / duration_target) * 100)
            logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s ({progress_pct:.1f}%) - {remaining:.1f}s remaining")
        else:
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            logger("info", f"Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # Print compression statistics if enabled
        if self.enable_compression and hasattr(self.writer, 'stats'):
            stats = self.writer.stats
            logger("info", f"  Events: {stats['total_events']:,} | "
                         f"Bytes: {stats['total_bytes_written']:,} | "
                         f"Files compressed: {stats['files_compressed']}")

    def trace(self):
        self.writer.write_log_header()
        self.probe_tracker.attach_probes()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO tracer started")
        logger("info", "Press Ctrl+C to exit")
        
        if self.writer.cache_sample_rate > 1:
            logger("info", f"Cache sampling enabled: 1:{self.writer.cache_sample_rate}")
        
        if self.enable_compression:
            logger("info", f"Automatic compression enabled (every {self.writer.compression_interval}s)")

        self.b["events"].open_perf_buffer(
            self._print_event, 
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

        start = time.time()
        last_progress_time = start
        progress_interval = 10 if self.verbose else 30  # Progress update interval in seconds
        
        if self.duration is not None:
            duration_target = self.duration
            end_time = start + duration_target
            logger("info", f"Tracing for {duration_target} seconds...")
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")

        self.polling_thread = PollingThread(self.b, True)
        self.polling_thread.create_thread()

        try:
            if self.duration is not None:
                remaining = duration_target
                while remaining > 0 and self.running:
                    sleep_time = min(0.1, remaining)
                    time.sleep(sleep_time)
                    
                    current = time.time()
                    remaining = end_time - current
                    
                    # Print progress at intervals
                    if current - last_progress_time >= progress_interval:
                        self._print_progress(start, duration_target)
                        last_progress_time = current
                        
                self._cleanup(None, None)
            else:
                # Run indefinitely until Ctrl+C
                while self.running:
                    time.sleep(0.1)
                    
                    current = time.time()
                    # Print progress at intervals
                    if current - last_progress_time >= progress_interval:
                        self._print_progress(start)
                        last_progress_time = current
                            
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
            
            summary = self.writer.get_output_summary()
            
            logger("info", "Please wait. Creating final archive...")
            
            archive_name = f"{self.writer.output_dir}/trace_archive_{time.strftime('%Y%m%d_%H%M%S')}.tar.gz"
            
            dirs_to_archive = []
            if self.is_uncompressed:
                dirs_to_archive = [
                    f"{self.writer.output_dir}/block",
                    f"{self.writer.output_dir}/vfs",
                    f"{self.writer.output_dir}/cache",
                    f"{self.writer.output_dir}/compressed"
                ]
            else:
                dirs_to_archive = [f"{self.writer.output_dir}/compressed"]
            
            existing_dirs = [d for d in dirs_to_archive if os.path.exists(d)]
            
            if existing_dirs:
                create_tar_gz(archive_name, existing_dirs)
                logger("info", f"Created archive: {archive_name}")
            
            logger("info", "=" * 60)
            logger("info", "Trace Summary:")
            logger("info", f"  Output directory: {summary['output_dir']}")
            logger("info", f"  File rotations: {summary['rotations']}")
            logger("info", f"  Compressed files: {len(summary['compressed_files'])}")
            if summary['compressed_files']:
                for f in summary['compressed_files'][:5]:  # Show first 5
                    logger("info", f"    - {f}")
                if len(summary['compressed_files']) > 5:
                    logger("info", f"    ... and {len(summary['compressed_files']) - 5} more")
            logger("info", f"  Active files: {len(summary['active_files'])}")
            logger("info", "=" * 60)
            
            if not self.is_uncompressed:
                logger("info", "Cleaning up uncompressed files...")
                for subdir in ['block', 'vfs', 'cache']:
                    path = f"{self.writer.output_dir}/{subdir}"
                    if os.path.exists(path):
                        shutil.rmtree(path)
                        
            logger("info", "Cleanup complete. Exited successfully.")