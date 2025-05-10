#!/usr/bin/python3

import subprocess
import signal
from bcc import BPF
import time
import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from .utils import logger
import threading

THRESHOLD_NS = 1000000

class IOTracer:
    def __init__(
            self, 
            output_dir: str,
            bpf_file: str = './tracer/vfs_prober.c',
            page_cnt: int = 8,
            analyze: bool = False,
            verbose: bool = False,
            duration: int = None,
            # debouncing_duration: int = THRESHOLD_NS,
            flush_interval: int = 60,
        ):
        global running, kprobes, json_events, json_block_events, json_outfile, event_count, last_event_time, flushing
        flushing = False
        running = True
        kprobes = []
        json_events = []
        json_block_events = []
        json_outfile = None
        event_count = 0
        last_event_time = 0
        self.bpf = None
        self.outfile = None
        # self.debouncing_duration = debouncing_duration

        self.log_output = ''
        self.log_block_output = ''

        self.output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output = f"{self.output_dir}/vfs_trace.log"
        self.output_json = f"{self.output_dir}/vfs_trace.json"
        self.output_block = f"{self.output_dir}/block_trace.log"
        self.output_block_json = f"{self.output_dir}/block_trace.json"

        self.bpf_file = bpf_file
        if page_cnt is None or page_cnt <= 0:
            logger("error", f"Invalid page count: {page_cnt}. Page count must be a positive integer.")
            sys.exit(1)
        self.page_cnt = page_cnt
        self.analyze = analyze
        self.verbose = verbose

        if duration is not None and duration <= 0:
            logger("error", f"Invalid duration: {duration}. Duration must be a positive integer.")
            sys.exit(1)

        self.duration = duration

        if (not duration is None) and (flush_interval == duration):
            logger("WARN", f"Flush interval is equal to the duration. Setting flush interval to {flush_interval - 10} second.")
            self.flush_interval = flush_interval - 10

        if flush_interval is not None and flush_interval <= 3:   
            logger("error", f"Invalid flush interval: {flush_interval}. Flush interval must be greater than 3 second.")
            sys.exit(1)
        self.flush_interval = flush_interval

        self.op_names = {
            1: "READ",
            2: "WRITE",
            3: "OPEN",
            4: "CLOSE",
            5: "FSYNC"
        }

        # Read the .c file
        try:
            with open(self.bpf_file, 'r') as f:
                self.bpf_text = f.read()
        except IOError as e:
            logger("error", f"could not read BPF file '{self.bpf_file}': {e}")
            sys.exit(1)

    # Compile the .c File
    def _compile(self):
        try:
            self.b = BPF(text=self.bpf_text, cflags=["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined"])
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            sys.exit(1)

    def _attach_kprobe(self,event, fn_name):
        global kprobes
        try:
            if self.verbose:
                logger("info", f"Attaching kprobe {event} to {fn_name}")
            k = self.b.attach_kprobe(event=event, fn_name=fn_name)
            kprobes.append((event, k))
            return True
        except Exception as e:
            logger("error", f"Failed to attach kprobe {event}: {e}")
            return False
        
    def _write_log(self):
        try:
            self.outfile = open(self.output, 'w', buffering=1)
            self.outfile_block = open(self.output_block, 'w', buffering=1)
            self.outfile.write("timestamp op_name pid comm filename inode size_val flags_str\n")
            self.outfile_block.write("timestamp pid comm sector nr_sectors operation\n")
            if self.verbose:
                logger("info", f"Logging to {self.output}")
        except IOError as e:
            logger("info", f"could not open output file '{self.output}': {e}")
            sys.exit(1)

    def _write_json(self):
        # JSON output
        try:
            json_outfile = self.output_json
            json_block_outfile = self.output_block_json
            if self.verbose:
                logger("info", f"Saving JSON data to {json_outfile} and {json_block_outfile} on completion")
        except IOError as e:
            logger("info", f"could not prepare JSON output file '{self.output_json}': {e}")
            self.output_json = None

    def debug(self):
        self._compile()
        self._attach_vfs_probes()
        while True:
            try:
                (task, pid, cpu, flags, ts, msg) = self.b.trace_fields()
                print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
            except KeyboardInterrupt:
                break

    def _print_event(self, cpu, data, size):
        global event_count, args, running, json_events, last_event_time
        
        event = self.b["events"].event(data)
        # print(f"{event.ts} FILESYSTEM LAYER -> PID:{event.pid}")
        op_name = self.op_names.get(event.op, "UNKNOWN")
        
        try:
            filename = event.filename.decode()
        except UnicodeDecodeError:
            filename = "[decode_error]"
        
        flags_str = self._format_flags(event.flags)
        
        raw_time = event.ts
        # if raw_time - last_event_time < self.debouncing_duration:
        #     return
        last_event_time = raw_time

        # ts = raw_time / 1000000000 
        # timestamp = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
        timestamp = raw_time
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        
        output = f"{timestamp} {op_name} {event.pid} {comm} {filename} {event.inode} {size_val} {flags_str}"
        
        # if self.verbose:
        #     print(output)
        
        # write to file
        self.log_output += output + "\n"
        
        # Store JSON
        if self.output_json:
            json_event = {
                "timestamp": timestamp,
                "op": op_name,
                "pid": event.pid,
                "comm": comm,
                "filename": filename,
                "inode": event.inode,
                "flags": flags_str
            }
            
            if event.op in [1, 2]:  # READ/WRITE
                json_event["size"] = event.size
            else:
                json_event["size"] = 0
            
            json_events.append(json_event)

    def _print_event_block(self, cpu, data, size):
        global event_count, args, running, json_block_events, last_event_time
        
        event = self.b["bl_events"].event(data)
        # op_name = self.op_names.get(event.op, "UNKNOWN")
        
        # print(f"{event.ts} BLOCK LAYER -> PID:{event.pid}")
        # print("%d %d %d" % (event.pid, event.ts, event.sector))
        timestamp = event.ts
        pid = event.pid
        comm = event.comm.decode('utf-8', errors='replace')
        sector = event.sector
        nr_sectors = event.nr_sectors
        ops_str = self._format_flags(event.op, is_block=True)
        output = f"{timestamp} {pid} {comm} {sector} {nr_sectors} {ops_str}"
         # write to file
        self.log_block_output += output + "\n"
        
        # Store JSON
        if self.output_block_json:
            json_event = {
                "timestamp": timestamp,
                "pid": event.pid,
                "comm": comm,
                "sector": sector,
                "nr_sectors": nr_sectors,
                "operation": ops_str
            }
            
            json_block_events.append(json_event)

    def _format_flags(self, flags, is_block=False):
        if not is_block:
            # https://github.com/analogdevicesinc/linux/blob/main/include/linux/blk_types.h#L370
            flag_map = {
                0o00000000: "O_RDONLY",
                0o00000001: "O_WRONLY", 
                0o00000002: "O_RDWR",
                0o00000100: "O_CREAT",
                0o00000200: "O_EXCL",
                0o00000400: "O_NOCTTY",
                0o00001000: "O_TRUNC",
                0o00002000: "O_APPEND",
                0o00004000: "O_NONBLOCK",
                0o00010000: "O_DSYNC",
                0o00040000: "O_DIRECT",
                0o00100000: "O_LARGEFILE",
                0o00200000: "O_DIRECTORY",
                0o00400000: "O_NOFOLLOW",
                0o01000000: "O_NOATIME",
                0o02000000: "O_CLOEXEC",
                0o04010000: "O_SYNC",
                0o010000000: "O_PATH",
                0o020200000: "O_TMPFILE"
            }
        
            # handle access mode specially
            access_mode = flags & 0o3  # mask with 0b11 (3 in decimal)
            access_str = None
            if access_mode == 0o0:
                access_str = "O_RDONLY"
            elif access_mode == 0o1:
                access_str = "O_WRONLY"
            elif access_mode == 0o2:
                access_str = "O_RDWR"
                
            result = []
            if access_str:
                result.append(access_str)
                
            # check for other flags
            # skip the access mode flags we already handled
            for flag, name in flag_map.items():
                if name in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
                    continue
                    
                # special handling for O_SYNC because it includes O_DSYNC
                if name == "O_SYNC" and flags & 0o04010000:
                    result.append(name)
                    continue
                    
                # specil handling for O_TMPFILE coz it includes O_DIRECTORY
                if name == "O_TMPFILE" and (flags & 0o020200000) == 0o020200000:
                    result.append(name)
                    # remove O_DIRECTORY if it's already in the list since it's part of O_TMPFILE
                    if "O_DIRECTORY" in result:
                        result.remove("O_DIRECTORY")
                    continue
                    
                # handle all other regular flags
                if name not in ["O_SYNC", "O_TMPFILE"] and flags & flag:
                    result.append(name)
            
            return "|".join(result) if result else "NO_FLAGS"
        else:
            # https://elixir.bootlin.com/linux/v6.14.6/source/include/linux/blk_types.h#L312
            op_types = {
                0: "REQ_OP_READ",
                1: "REQ_OP_WRITE",
                2: "REQ_OP_FLUSH",
                3: "REQ_OP_DISCARD",
                5: "REQ_OP_SECURE_ERASE",
                7: "REQ_OP_ZONE_APPEND",
                9: "REQ_OP_WRITE_ZEROES",
                10: "REQ_OP_ZONE_OPEN",
                11: "REQ_OP_ZONE_CLOSE",
                12: "REQ_OP_ZONE_FINISH",
                13: "REQ_OP_ZONE_RESET",
                15: "REQ_OP_ZONE_RESET_ALL",
                34: "REQ_OP_DRV_IN",
                35: "REQ_OP_DRV_OUT",
                36: "REQ_OP_LAST"
            }

            result = [op_types.get(flags, f"UNKNOWN_OP({flags})")]
            return "|".join(result) if result else "NO_FLAGS"

    def _flush(self):
        global json_events, json_block_events, flushing
        
        logger("FLUSH", "Flushing data...", True)
        json_events_copy = json_events
        json_block_events_copy = json_block_events
        log_output_copy = self.log_output
        log_block_output_copy = self.log_block_output
        json_events = []
        json_block_events = []
        self.log_output = ''
        self.log_block_output = ''

        self._write_to_disk(
            json_events_copy, 
            json_block_events_copy, 
            log_output_copy, 
            log_block_output_copy
        )

        if self.verbose:
            logger("FLUSH", f"Flushing complete!", True)
        flushing = False
        time.sleep(1)
        

    def _detach_kprobes(self):
        global kprobes
        # detach kprobes
        for event, k in kprobes:
            try:
                self.b.detach_kprobe(event=event)
                if self.verbose:
                    logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def _write_to_disk(self, json_events_copy, json_block_events_copy, log_output_copy, log_block_output_copy):
        if self.output_json:
            try:
                with open(self.output_json, 'w') as f:
                    json.dump(json_events_copy, f, indent=2)
                if self.verbose:
                    logger("WRITE", f"Saved {len(json_events_copy)} events to {self.output_json}")
                with open(self.output_block_json, 'w') as f:
                    json.dump(json_block_events_copy, f, indent=2)
                if self.verbose:
                    logger("WRITE", f"Saved {len(json_block_events_copy)} events to {self.output_block_json}")
            except Exception as e:
                logger("WRITE ERROR", f"Failed to save JSON data: {e}")

            try:
                self.outfile.write(log_output_copy)
                if self.verbose:
                    logger("WRITE", f"Saved log to {self.output}")
                self.outfile_block.write(log_block_output_copy)          
                if self.verbose:      
                    logger("WRITE", f"Saved log block to {self.output_block}")
            except Exception as e:
                logger("WRITE ERROR", f"Failed to save log data: {e}")

    def _cleanup(self,signum, frame):
        global running, json_events, json_block_events

        running = False
        
        # detach kprobes
        self._detach_kprobes()
                
        self._write_to_disk(
            json_events,
            json_block_events,
            self.log_output,
            self.log_block_output
        )
        
        if self.verbose:
            logger("CLEANUP", "Cleanup complete")

    def _lost_cb(self,lost):
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

    def _attach_vfs_probes(self):
        global kprobes

        try:
            self._attach_kprobe("vfs_read", "trace_vfs_read")
            self._attach_kprobe("vfs_write", "trace_vfs_write")
            self._attach_kprobe("vfs_open", "trace_vfs_open")
            self._attach_kprobe("vfs_fsync", "trace_vfs_fsync")
            self._attach_kprobe("submit_bio","trace_submit_bio")
            if not self._attach_kprobe("vfs_fsync_range", "trace_vfs_fsync_range"):
                logger("info", "vfs_fsync_range not found, using only vfs_fsync")
            self._attach_kprobe("__fput", "trace_fput") 
            
            if not kprobes:
                logger("error", "no kprobes attached successfully!")
                sys.exit(1)   
        except Exception as e:
            logger("error", f"failed to attach to kernel functions: {e}")
            sys.exit(1)

    def _is_time_to_flush(self,time) -> bool:
        global flushing
        if (int(time % self.flush_interval) == 0 and int(time) != 0):
            flushing = True
            return True
        else:
            return False

    def _polling_thread(self):
        global polling_active
        while polling_active:
            try:
                self.b.perf_buffer_poll(timeout=50)
            except Exception as e:
                logger("error", f"Error in polling thread: {e}")
                time.sleep(0.01)

    def _create_thread(self):
        global polling_active
        polling_active = True

        poller = threading.Thread(target=self._polling_thread)
        poller.daemon = True
        poller.start()

    def trace(self):
        global flushing,running, kprobes, json_events, json_outfile, event_count, last_event_time, polling_active
        self._write_log()
        self._write_json()
        self._compile()
        self._attach_vfs_probes()


        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO tracer started")
        logger("info","Press Ctrl+C to exit")
        # if self.args.limit > 0:
        #     logger("info", f"Limiting to {args.limit} events")


        self.b["events"].open_perf_buffer(self._print_event, page_cnt=self.page_cnt, lost_cb=self._lost_cb)
        self.b["bl_events"].open_perf_buffer(self._print_event_block, page_cnt=self.page_cnt, lost_cb=self._lost_cb)

        start = time.time()
        if self.duration is not None:
            duration_target = self.duration
            end_time = start + duration_target
            logger("info", f"Tracing for {duration_target} seconds...")
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")


        self._create_thread()

        try:
            if self.duration is not None:
                remaining = duration_target
                while remaining > 0 and running:
                    sleep_time = min(0.1, remaining)
                    time.sleep(sleep_time)
                    
                    current = time.time()
                    remaining = end_time - current

                    self._is_time_to_flush(current - start)
                    if flushing:
                        self._flush()
                    
                    if self.verbose and int(current) > int(current - sleep_time):
                        elapsed = current - start
                        logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s")
            else:
                while running:
                    time.sleep(0.1)
                    current = time.time()
                    self._is_time_to_flush(current - start)
                    if flushing:
                        self._flush()
                        
                        
                if self.verbose:
                    logger("info", f"Main thread: time limit reached after {time.time() - start:.2f}s")
                running = False
        except KeyboardInterrupt:
            logger("info", "Keyboard interrupt received")
            running = False
        except Exception as e:
            logger("error", f"Main loop error: {e}")
        finally:
            polling_active = False
            
            time.sleep(0.2)
            
            actual_duration = time.time() - start
            if self.verbose:
                logger("info", f"Trace completed after {actual_duration:.2f} seconds (target: {duration_target}s)")
            print()
            logger("info", "Exiting...")