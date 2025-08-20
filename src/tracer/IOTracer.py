#!/usr/bin/python3

import shutil
import signal
from bcc import BPF
import time
import sys
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
            cache_sample_rate:  int = 1
        ):
        self.writer             = WriteManager(output_dir, split_threshold)
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
            self.b = BPF(src_file=bpf_file.encode(), cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined"])
            self.probe_tracker = KernelProbeTracker(self.b)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            sys.exit(1)

    def _print_event(self, cpu, data, size):        
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = "[anonymous file]" if self.anonymous else f'"{event.filename.decode()}"'
            filepath = "[anonymous file]" if self.anonymous else f'"{self.path_resolver.resolve_path(event.inode, event.pid, event.filename.decode(errors='replace'))}"'
        except UnicodeDecodeError:
            filename = "[decode_error]"
            filepath = "[decode_error]"
        
        flags_str = self.flag_mapper.format_fs_flags(event.flags)
        timestamp = event.ts
        
        try:
            comm = "[anonymous process]" if self.anonymous else event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        output = f"{timestamp} {op_name} {event.pid} {comm.replace(' ','_')} {filename.replace(' ','_')} {filepath.replace(' ','_')} {event.inode} {size_val} {flags_str}"
        
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
        
        logger("info", "Performing final flush...")
        self.writer.write_to_disk()
        
        self.writer.close_handles()

        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self, lost):
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def trace(self):
        self.writer.write_log_header()
        self.probe_tracker.attach_probes()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO tracer started")
        logger("info", "Press Ctrl+C to exit")
        
        if self.writer.cache_sample_rate > 1:
            logger("info", f"Cache sampling enabled: 1:{self.writer.cache_sample_rate}")

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
                    
                    if self.verbose and int(current) % 10 == 0 and int(current) > int(current - sleep_time):
                        elapsed = current - start
                        logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s")
                        
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
            
            create_tar_gz(
                f"{self.writer.output_dir}/raw_trace_{time.strftime('%Y%m%d_%H%M%S')}.tar.gz", 
                [f"{self.writer.output_dir}/block", 
                 f"{self.writer.output_dir}/vfs", 
                 f"{self.writer.output_dir}/cache"]
            )
            
            logger("info", "Compression complete. Cleaning up...")

            if self.is_uncompressed:
                shutil.rmtree(f"{self.writer.output_dir}/block")
                shutil.rmtree(f"{self.writer.output_dir}/vfs")
                shutil.rmtree(f"{self.writer.output_dir}/cache")
            
            logger("info", "Cleanup complete. Exited successfully.")