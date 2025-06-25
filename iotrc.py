#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer
from src.tracer.BlockToFS import BlockToFS

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace VFS syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging, must be new!')
    parser.add_argument('-b', '--bpf-file', type=str, default='./src/tracer/prober/vfs_prober.c', help='BPF C source file path')
    parser.add_argument('-p', '--page-cnt', type=int, default=8, help='Number of pages for perf buffer (default 8)')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-d', '--duration', type=int, help='Duration to run the tracer in seconds. Default is NULL (run indefinitely)')
    parser.add_argument('-f', '--flush_threshold', type=int, default=50000, help='Buffered flush threshold in array length (default 5000)')
    parser.add_argument('-tw', '--time-window', type=int, default=5_000_000, help='Time window for matching PIDs (default 5_000_000 ns)')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file=parse_args.bpf_file.strip(),
        page_cnt=parse_args.page_cnt,
        verbose=parse_args.verbose,
        duration=parse_args.duration,
        flush_threshold=parse_args.flush_threshold,
    )
    # tracer.debug()
    tracer.trace()
    log_output = tracer.writer.output_vfs_file
    log_block = tracer.writer.output_block_file
    time_window = parse_args.time_window

