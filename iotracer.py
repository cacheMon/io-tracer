#!/usr/bin/python3

import signal
from bcc import BPF
import time
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
from utils import logger

running = True

# Track attached probes for explicit detachment
kprobes = []

# command line arguments
parser = argparse.ArgumentParser(description='Trace VFS syscalls')
parser.add_argument('-o', '--output', type=str, help='Output file for logging')
parser.add_argument('-l', '--limit', type=int, default=0, help='Limit number of events to capture (0 = unlimited)')
parser.add_argument('-b', '--bpf-file', type=str, default='vfs_prober.c', help='BPF C source file path')
parser.add_argument('-p', '--page-cnt', type=int, default=8, help='Number of pages for perf buffer (default 8)')
args = parser.parse_args()

try:
    with open(args.bpf_file, 'r') as f:
        bpf_text = f.read()
except IOError as e:
    logger("error", f"could not read BPF file '{args.bpf_file}': {e}")
    sys.exit(1)

try:
    b = BPF(text=bpf_text) # init BPF
except Exception as e:
    logger("error", f"failed to initialize BPF: {e}")
    sys.exit(1)

# Function to safely attach kprobes and keep track of them
def attach_kprobe(event, fn_name):
    global kprobes
    try:
        k = b.attach_kprobe(event=event, fn_name=fn_name)
        kprobes.append((event, k))
        return True
    except Exception as e:
        logger("error", f"Failed to attach kprobe {event}: {e}")
        return False

try:
    # kernel functions
    attach_kprobe("vfs_read", "trace_vfs_read")
    attach_kprobe("vfs_write", "trace_vfs_write")
    attach_kprobe("vfs_open", "trace_vfs_open")
    attach_kprobe("vfs_fsync", "trace_vfs_fsync")
    if not attach_kprobe("vfs_fsync_range", "trace_vfs_fsync_range"):
        logger("info", "vfs_fsync_range not found, using only vfs_fsync")
    attach_kprobe("__fput", "trace_fput") 
    
    if not kprobes:
        logger("error", "No kprobes attached successfully!")
        sys.exit(1)
        
except Exception as e:
    logger("error", f"failed to attach to kernel functions: {e}")
    sys.exit(1)

op_names = {
    1: "READ",
    2: "WRITE",
    3: "OPEN",
    4: "CLOSE",
    5: "FSYNC"
}

# logger
outfile = None
if args.output:
    try:
        # Use line buffering for better performance
        outfile = open(args.output, 'w', buffering=1)
        logger("info", f"logging to {args.output}")
    except IOError as e:
        logger("info", f"could not open output file '{args.output}': {e}")
        sys.exit(1)

event_count = 0 # event limiter

def print_event(cpu, data, size):
    global event_count, args, running
    
    event = b["events"].event(data)
    op_name = op_names.get(event.op, "UNKNOWN")
    
    try:
        filename = event.filename.decode()
    except UnicodeDecodeError:
        filename = "[decode_error]"
    
    flags_str = format_flags(event.flags)
    
    ts = event.ts / 1000000000 
    timestamp = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
    
    try:
        comm = event.comm.decode()
    except UnicodeDecodeError:
        comm = "[decode_error]"
    
    if event.op in [1, 2]:
        output = f"[{timestamp}] {op_name}: PID {event.pid} ({comm}): " \
                 f"file '{filename}' (inode: {event.inode}), " \
                 f"size: {event.size} bytes, LBA: {event.lba}, " \
                 f"flags: {flags_str}"
    else:  
        output = f"[{timestamp}] {op_name}: PID {event.pid} ({comm}): " \
                 f"file '{filename}' (inode: {event.inode}), " \
                 f"flags: {flags_str}"
    
    print(output)
    
    # write to file
    if outfile:
        outfile.write(output + "\n")
    
    # limiter
    if args.limit > 0:
        event_count += 1
        if event_count >= args.limit:
            running = False

def format_flags(flags):
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

def cleanup(signum, frame):
    global running, kprobes
    
    running = False
    logger("info", "Detaching probes (this may take a moment)...")
    
    # Explicitly detach all kprobes we tracked
    for event, k in kprobes:
        try:
            b.detach_kprobe(event=event)
            logger("info", f"Detached kprobe: {event}")
        except Exception as e:
            logger("error", f"Error detaching {event}: {e}")
    
    if outfile:
        logger("info", "Closing output file...")
        outfile.close()
    
    logger("info", "Cleanup complete")

# Register signal handlers
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

logger("info", "starting VFS syscall tracer...")
print("tracing VFS calls (read, write, open, close, fsync)... Press Ctrl+C to exit")
if args.limit > 0:
    logger("info", f"Limiting to {args.limit} events")
print("\n%-12s %-6s %-16s %-30s %-10s %-12s" % 
      ("OP", "PID", "COMM", "FILENAME", "INODE", "SIZE/LBA"))

# Open perf buffer with configurable page count for performance tuning
b["events"].open_perf_buffer(print_event, page_cnt=args.page_cnt)

# Main loop with better error handling
try:
    while running:
        try:
            # Short timeout to check running flag frequently
            b.perf_buffer_poll(timeout=50)
        except KeyboardInterrupt:
            running = False
        except Exception as e:
            logger("error", f"error in perf buffer polling: {e}")
            time.sleep(0.1) 
except Exception as e:
    logger("error", f"Main loop error: {e}")
finally:
    cleanup(None, None)
    logger("info", "Exiting...")