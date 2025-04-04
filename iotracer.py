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

# command linez
parser = argparse.ArgumentParser(description='Trace VFS syscalls')
parser.add_argument('-p', '--pid', type=int, help='Filter by process ID')
parser.add_argument('-c', '--command', type=str, help='Filter by command name')
parser.add_argument('-o', '--output', type=str, help='Output file for logging')
parser.add_argument('-t', '--type', type=str, help='Filter by operation type (READ,WRITE,OPEN,CLOSE,FSYNC)')
parser.add_argument('-f', '--filepath', type=str, help='Filter by filepath substring')
parser.add_argument('-l', '--limit', type=int, default=0, help='Limit number of events to capture (0 = unlimited)')
parser.add_argument('-b', '--bpf-file', type=str, default='vfs_prober.c', help='BPF C source file path')
args = parser.parse_args()

try:
    with open(args.bpf_file, 'r') as f:
        bpf_text = f.read()
except IOError as e:
    logger("error", f"could not read BPF file '{args.bpf_file}': {e}")
    sys.exit(1)

# filtering PID 
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', str(args.pid))
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

try:
    b = BPF(text=bpf_text) # init BPF
except Exception as e:
    logger("error", f"failed to initialize BPF: {e}")
    sys.exit(1)

try:
    # kernel functions
    b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
    b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
    b.attach_kprobe(event="vfs_open", fn_name="trace_vfs_open")
    b.attach_kprobe(event="vfs_fsync", fn_name="trace_vfs_fsync")
    try:
        b.attach_kprobe(event="vfs_fsync_range", fn_name="trace_vfs_fsync_range")
    except Exception:
        logger("info", "vfs_fsync_range not found, using only vfs_fsync")
    b.attach_kprobe(event="__fput", fn_name="trace_fput") 
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
        outfile = open(args.output, 'w')
        logger("info", f"logging to {args.output}")
    except IOError as e:
        logger("info", f"could not open output file '{args.output}': {e}")
        sys.exit(1)

event_count = 0 # event limiter

def print_event(cpu, data, size):
    global event_count, args
    
    event = b["events"].event(data)
    op_name = op_names.get(event.op, "UNKNOWN")
    
    if args.command and args.command.lower() not in event.comm.decode().lower():
        return
    
    if args.type and args.type.upper() != op_name:
        return
    
    try:
        filename = event.filename.decode()
    except UnicodeDecodeError:
        filename = "[decode_error]"
        
    if args.filepath and args.filepath.lower() not in filename.lower():
        return
    
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
        outfile.flush()
    
    # limiter
    if args.limit > 0:
        event_count += 1
        if event_count >= args.limit:
            cleanup(None, None)

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
    logger("info", "Detaching...")
    if outfile:
        outfile.close()
    exit()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

logger("info", "starting VFS syscall tracer...")
print("tracing VFS calls (read, write, open, close, fsync)... Press Ctrl+C to exit")
if args.pid:
    logger("info", f"Filtering for PID: {args.pid}")
if args.command:
    logger("info", f"Filtering for command: {args.command}")
if args.type:
    logger("info", f"Filtering for operation type: {args.type}")
if args.filepath:
    logger("info", f"Filtering for files containing: {args.filepath}")
if args.limit > 0:
    logger("info", f"Limiting to {args.limit} events")
print("\n%-12s %-6s %-16s %-30s %-10s %-12s" % 
      ("OP", "PID", "COMM", "FILENAME", "INODE", "SIZE/LBA"))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        cleanup(None, None)
