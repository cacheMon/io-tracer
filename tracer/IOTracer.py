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
        global running, kprobes, json_events, json_outfile, event_count, last_event_time
        running = True
        kprobes = []
        json_events = []
        json_outfile = None
        event_count = 0
        last_event_time = 0
        self.bpf = None
        self.outfile = None
        self.debouncing_duration = debouncing_duration

        self.output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output = f"{self.output_dir}/vfs_trace.log"
        self.output_json = f"{self.output_dir}/vfs_trace.json"

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
            k = self.b.attach_kprobe(event=event, fn_name=fn_name)
            kprobes.append((event, k))
            return True
        except Exception as e:
            logger("error", f"Failed to attach kprobe {event}: {e}")
            return False
        
    def _write_log(self):
        try:
            self.outfile = open(self.output, 'w', buffering=1)
            # outfile.write("timestamp op_name pid comm filename inode size_val lba_val flags_str\n")
            logger("info", f"logging to {self.output}")
        except IOError as e:
            logger("info", f"could not open output file '{self.output}': {e}")
            sys.exit(1)

    def _write_json(self):
        # JSON output
        try:
            json_outfile = self.output_json
            logger("info", f"Will save JSON data to {json_outfile} on completion")
        except IOError as e:
            logger("info", f"could not prepare JSON output file '{self.output_json}': {e}")
            self.output_json = None

    def _print_event(self, cpu, data, size):
        global event_count, args, running, json_events, last_event_time
        
        event = self.b["events"].event(data)
        op_name = self.op_names.get(event.op, "UNKNOWN")
        
        try:
            filename = event.filename.decode()
        except UnicodeDecodeError:
            filename = "[decode_error]"
        
        flags_str = self._format_flags(event.flags)
        
        raw_time = event.ts
        if raw_time - last_event_time < self.debouncing_duration:
            return
        last_event_time = raw_time

        ts = raw_time / 1000000000 
        timestamp = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
        
        size_val = event.size if event.size is not None else 0
        lba_val = event.lba if event.lba is not None else 0
        
        output = f"{timestamp} {op_name} {event.pid} {comm} {filename} {event.inode} {size_val} {lba_val} {flags_str}"
        
        if self.verbose:
            print(output)
        
        # write to file
        if self.outfile:
            self.outfile.write(output + "\n")
        
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
        
        # limiter
        # if self.limit > 0:
        #     event_count += 1
        #     if event_count >= self.limit:
        #         running = False

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
        global running, kprobes, json_events, json_outfile
        
        running = False
        logger("info", "Detaching probes (this may take a moment)...")
        
        # detach kprobes
        for event, k in kprobes:
            try:
                self.b.detach_kprobe(event=event)
                logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")
        
        if self.outfile:
            logger("info", "Closing output file...")
            self.outfile.close()
        
        if self.output_json and json_events:
            try:
                with open(self.output_json, 'w') as f:
                    json.dump(json_events, f, indent=2)
                logger("info", f"Saved {len(json_events)} events to {self.output_json}")
                
                if self.analyze and self.output:
                    logger("info", "Running analyzer on trace data...")
                    try:
                        subprocess.run(['python3', '../analyzer/analyzer.py', self.output, 
                                    '-o', f"{Path(self.output).stem}_analysis"])
                    except Exception as e:
                        logger("error", f"Failed to run analyzer: {e}")
            except Exception as e:
                logger("error", f"Failed to save JSON data: {e}")
        
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
        self._write_log()
        self._write_json()


        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "VFS syscall tracer started")
        logger("info","tracing VFS calls (read, write, open, close, fsync)... Press Ctrl+C to exit")
        # if self.args.limit > 0:
        #     logger("info", f"Limiting to {args.limit} events")


        self.b["events"].open_perf_buffer(self._print_event, page_cnt=self.page_cnt, lost_cb=self._lost_cb)

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