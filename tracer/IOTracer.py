#!/usr/bin/python3

import signal
from bcc import BPF
import time
import sys
from .utils import logger
from .WriterManager import WriteManager
from .FlagMapper import FlagMapper
from .KernelProbeTracker import KernelProbeTracker
from .PollingThread import PollingThread

class IOTracer:
    def __init__(
            self, 
            output_dir:         str,
            bpf_file:           str = './tracer/prober/vfs_prober.c',
            page_cnt:           int = 8,
            verbose:            bool = False,
            duration:           int = None,
            flush_threshold:    int = 5000,
        ):
        self.writer             = WriteManager(output_dir)
        self.flag_mapper        = FlagMapper()

        self.flushing           = False
        self.running            = True
        self.bpf                = None
        self.verbose            = verbose
        self.duration           = duration
        self.flush_threshold    = flush_threshold


        if page_cnt is None or page_cnt <= 0:
            logger("error", f"Invalid page count: {page_cnt}. Page count must be a positive integer.")
            sys.exit(1)
        self.page_cnt = page_cnt

        if duration is not None and duration <= 0:
            logger("error", f"Invalid duration: {duration}. Duration must be a positive integer.")
            sys.exit(1)

        try:
            self.b = BPF(src_file=bpf_file, cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined"])
            self.probe_tracker = KernelProbeTracker(self.b)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            sys.exit(1)

    def _print_event(self, cpu, data, size):        
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = event.filename.decode()
        except UnicodeDecodeError:
            filename = "[decode_error]"
        
        flags_str = self.flag_mapper.format_fs_flags(event.flags)
        timestamp = event.ts
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        output = f"{timestamp} {op_name} {event.pid} {comm.replace(' ','_')} {filename.replace(' ','_')} {event.inode} {size_val} {flags_str}"


        if self.verbose:
            print(output)
        
        # write to file
        self.writer.append_fs_log(output)
        
        # Store JSON
        json_event = {
            "timestamp" : timestamp,
            "op"        : op_name,
            "pid"       : event.pid,
            "comm"      : comm,
            "filename"  : filename,
            "inode"     : event.inode,
            "flags"     : flags_str
        }
        
        if event.op in [1, 2]:  # READ/WRITE
            json_event["size"] = event.size
        else:
            json_event["size"] = 0
        
        self.writer.append_fs_json(json_event)

    def _print_event_block(self, cpu, data, size):        
        event = self.b["bl_events"].event(data)
        
        timestamp = event.ts
        pid = event.pid
        comm = event.comm.decode('utf-8', errors='replace')
        sector = event.sector
        nr_sectors = event.nr_sectors
        ops_str = self.flag_mapper.format_block_operation(event.op)
        output = f"{timestamp} {pid} {comm.replace(' ','_')} {sector} {nr_sectors} {ops_str}"

        self.writer.append_block_log(output)
        
        # Store JSON
        json_event = {
            "timestamp"     : timestamp,
            "pid"           : event.pid,
            "comm"          : comm,
            "sector"        : sector,
            "nr_sectors"    : nr_sectors,
            "operation"     : ops_str
        }

        self.writer.append_block_json(json_event)

    def _flush(self):        
        logger("FLUSH", "Flushing data...", True)
        self.writer.write_to_disk()
        logger("FLUSH", f"Flushing complete!", True)

        if self.verbose:
            logger("FLUSH", f"Flushing complete!", True)

        self.flushing = False
        time.sleep(1)

    def _is_time_to_flush(self):
        if (self.writer.isEventsBigEnough(self.flush_threshold)) and (not self.flushing): 
            self.flushing = True
            self._flush()

    def _cleanup(self,signum, frame):
        self.running = False
    
        # detach kprobes
        self.probe_tracker.detach_kprobes()
                
        self.writer.write_to_disk()
        self.writer.close_handles()

        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self,lost):
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def trace(self):
        self.writer.write_log_header()
        self.probe_tracker.attach_kprobes()


        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO tracer started")
        logger("info","Press Ctrl+C to exit")

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

                    self._is_time_to_flush()
                    if self.flushing:
                        self._flush()
                    
                    if self.verbose and int(current) > int(current - sleep_time):
                        elapsed = current - start
                        logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s")
                self._cleanup(None, None)
            else:
                # Cleanup on Ctrl+C
                while self.running:
                    time.sleep(0.1)
                    self._is_time_to_flush()
                    if self.flushing:
                        self._flush()
                if self.verbose:
                    logger("info", f"Main thread: time limit reached after {time.time() - start:.2f}s")
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
                logger("info", f"Trace completed after {actual_duration:.2f} seconds (target: {duration_target}s)")
            print()
            logger("info", "Exiting...")