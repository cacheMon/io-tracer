#!/usr/bin/python3

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
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(output_dir, "linux_trace" ,capture_machine_id().upper() ,str(timestamp))

        temp_version = version if not developer_mode else f"vdev"
        if developer_mode:
            logger("warning", "Developer mode enabled: extra logs and checks are active.")
        self.upload_manager     = ObjectStorageManager(temp_version)
        self.automatic_upload   = automatic_upload

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
            self.b = BPF(src_file=bpf_file.encode(), cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined"])
            self.probe_tracker = KernelProbeTracker(self.b)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            sys.exit(1)

    def _print_event(self, cpu, data, size):        
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = event.filename.decode()
            if self.anonymous:
                filename = hash_filename_in_path(Path(filename))
        except UnicodeDecodeError:
            filename = "[decode_error]"
            filepath = "[decode_error]"
        
        timestamp = datetime.today()
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        output = format_csv_row(timestamp, op_name, event.pid, comm, filename, size_val, event.inode)

        self.writer.append_fs_log(output)
        
    def _print_event_cache(self, cpu, data, size):       
        event = self.b["cache_events"].event(data)
        timestamp = datetime.today()
        pid = event.pid
        comm = event.comm.decode('utf-8', errors='replace')
        hit = "HIT" if event.type == 0 else "MISS"

        output = format_csv_row(timestamp, pid, comm, hit)
        self.writer.append_cache_log(output)

    def _print_event_block(self, cpu, data, size):        
        event = self.b["bl_events"].event(data)
        
        timestamp = datetime.today()
        pid = event.pid
        tid = event.tid
        comm = event.comm.decode('utf-8', errors='replace')
        sector = event.sector
        nr_sectors = event.nr_sectors
        ops_str = event.op.decode('utf-8', errors='replace')
        ops_str = self.flag_mapper.format_block_ops(ops_str)
        latency_ns = event.latency_ns
        latency_ms = latency_ns / 1_000_000.0
        cpu_id = event.cpu_id
        ppid = event.ppid
        bio_size = event.bio_size

        output = format_csv_row(timestamp, pid, comm, sector, ops_str, bio_size, latency_ms, tid, nr_sectors, cpu_id, ppid)


        if (sector == 0 and nr_sectors == 0) or (sector == '0' and nr_sectors == '0'):
            if self.verbose:
                print("="*50)
                print("Warning: LBA 0 detected in block trace")
                print(output)
                print("="*50)

        self.writer.append_block_log(output)

    def _print_event_net(self, cpu, data, size):
        e = self.b["net_events"].event(data)
        ts = datetime.today()
        pid = e.pid
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        size_bytes = e.size_bytes
        ty = "send" if e.dir == 0 else "receive"

        if e.ipver == 4:
            s_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", e.saddr_v4))
            d_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", e.daddr_v4))
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
        self.running = False
    
        self.probe_tracker.detach_kprobes()
        
        logger("info", "Performing final flush...")
        self.fs_snapper.stop_snapper()
        self.process_snapper.stop_snapper()
        self.writer.write_to_disk()
        
        self.writer.close_handles()

        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self, lost):
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def trace(self):
        self.probe_tracker.attach_probes()
        if self.automatic_upload:
            self.upload_manager.start_worker()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO Tracer is running")
        logger("info", "Press Ctrl+C to exit")
        self.system_snapper.capture_spec_snapshot()
        self.fs_snapper.run()
        self.process_snapper.run()

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

