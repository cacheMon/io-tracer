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
            duration: int = 10,
            debouncing_duration: int = THRESHOLD_NS,
        ):
        global running, kprobes, json_events, json_block_events, json_outfile, event_count, last_event_time
        running = True
        kprobes = []
        json_events = []
        json_block_events = []
        json_outfile = None
        event_count = 0
        last_event_time = 0
        self.bpf = None
        self.outfile = None
        self.debouncing_duration = debouncing_duration

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
        self.page_cnt = page_cnt
        self.analyze = analyze
        self.verbose = verbose
        self.duration = duration

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
                self. bpf_text = f.read()
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
            self.outfile.write("timestamp op_name pid comm filename inode size_val lba_val flags_str\n")
            self.outfile_block.write("timestamp pid comm sector nr_sectors\n")
            logger("info", f"logging to {self.output}")
        except IOError as e:
            logger("info", f"could not open output file '{self.output}': {e}")
            sys.exit(1)

    def _write_json(self):
        # JSON output
        try:
            json_outfile = self.output_json
            json_block_outfile = self.output_block_json
            logger("info", f"Will save JSON data to {json_outfile} and {json_block_outfile}  on completion")
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
        lba_val = event.lba if event.lba is not None else 0
        
        output = f"{timestamp} {op_name} {event.pid} {comm} {filename} {event.inode} {size_val} {flags_str}"
        
        if self.verbose:
            print(output)
        
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
                json_event["lba"] = event.lba
            else:
                json_event["size"] = 0
                json_event["lba"] = 0
            
            json_events.append(json_event)

    def _print_event_block(self, cpu, data, size):
        global event_count, args, running, json_block_events, last_event_time
        
        event = self.b["bl_events"].event(data)
        # op_name = self.op_names.get(event.op, "UNKNOWN")
        
        # print(f"{event.ts} BLOCK LAYER -> PID:{event.pid}")
        # print("%d %d %d" % (event.pid, event.ts, event.sector))
        timestamp = event.ts
        pid = event.pid
        comm = event.comm
        sector = event.sector
        nr_sectors = event.nr_sectors
        output = f"{timestamp} {pid} {comm} {sector} {nr_sectors}"
        # print(event.rwbs)
         # write to file
        self.log_block_output += output + "\n"
        
        # Store JSON
        if self.output_block_json:
            json_event = {
                "timestamp": timestamp,
                "pid": event.pid,
                "comm": comm.decode(),
                "sector": sector,
                "nr_sectors": nr_sectors
            }
            
            json_block_events.append(json_event)

    def _format_flags(self, flags):
        flag_map = {
            os.O_RDONLY: "O_RDONLY",
            os.O_WRONLY: "O_WRONLY",
            os.O_RDWR: "O_RDWR",
            os.O_APPEND: "O_APPEND",
            os.O_NONBLOCK: "O_NONBLOCK",
            os.O_DIRECT: "O_DIRECT",
            os.O_SYNC: "O_SYNC",
            os.O_CREAT: "O_CREAT",
            os.O_TRUNC: "O_TRUNC",
            os.O_EXCL: "O_EXCL"
        }
        
        result = []
        for flag, name in flag_map.items():
            if flags & flag:
                result.append(name)
        
        return "|".join(result) if result else "0"
    
    def _cleanup(self,signum, frame):
        global running, kprobes, json_events, json_block_events, json_outfile
        self._write_log()
        self._write_json()

        running = False
        logger("info", "Detaching probes (this may take a moment)...")
        
        # detach kprobes
        for event, k in kprobes:
            try:
                self.b.detach_kprobe(event=event)
                logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")
                
        if self.output_json:
            try:
                with open(self.output_json, 'w') as f:
                    json.dump(json_events, f, indent=2)
                logger("info", f"Saved {len(json_events)} events to {self.output_json}")
                with open(self.output_block_json, 'w') as f:
                    json.dump(json_block_events, f, indent=2)
                logger("info", f"Saved {len(json_block_events)} events to {self.output_block_json}")
            except Exception as e:
                logger("error", f"Failed to save JSON data: {e}")

            try:
                self.outfile.write(self.log_output)
                logger("info", f"Saved log to {self.output}")
                self.outfile_block.write(self.log_block_output)                
                logger("info", f"Saved log block to {self.output_block}")
            except Exception as e:
                logger("error", f"Failed to save log data: {e}")
        
        if self.outfile or self.outfile_block:
            logger("info", "Closing output file...")
            self.outfile.close()
            self.outfile_block.close()


        logger("info", "Cleanup complete")

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

    def trace(self):
        global running, kprobes, json_events, json_outfile, event_count, last_event_time

        self._compile()
        self._attach_vfs_probes()


        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "VFS syscall tracer started")
        logger("info","tracing VFS calls (read, write, open, close, fsync)... Press Ctrl+C to exit")
        # if self.args.limit > 0:
        #     logger("info", f"Limiting to {args.limit} events")


        self.b["events"].open_perf_buffer(self._print_event, page_cnt=self.page_cnt, lost_cb=self._lost_cb)
        self.b["bl_events"].open_perf_buffer(self._print_event_block, page_cnt=self.page_cnt, lost_cb=self._lost_cb)

        start = time.time()
        duration_target = self.duration
        end_time = start + duration_target
        logger("info", f"Tracing for {duration_target} seconds...")


        polling_active = True

        def polling_thread():
            while polling_active:
                try:
                    self.b.perf_buffer_poll(timeout=50)
                except Exception as e:
                    logger("error", f"Error in polling thread: {e}")
                    time.sleep(0.01)

        poller = threading.Thread(target=polling_thread)
        poller.daemon = True
        poller.start()

        try:
            remaining = duration_target
            while remaining > 0 and running:
                sleep_time = min(0.1, remaining)
                time.sleep(sleep_time)
                
                current = time.time()
                remaining = end_time - current
                
                if self.verbose and int(current) > int(current - sleep_time):
                    elapsed = current - start
                    logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s")
            
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
            logger("info", f"Trace completed after {actual_duration:.2f} seconds (target: {duration_target}s)")
            
            self._cleanup(None, None)
            logger("info", "Exiting...")