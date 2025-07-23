#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer
from src.tracer.BlockToFS import BlockToFS

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging, must be new!')
    parser.add_argument('-b', '--bpf-file', type=str, default='./src/tracer/prober/prober.c', help='BPF C source file path')
    parser.add_argument('-p', '--page-cnt', type=int, default=8, help='Number of pages for perf buffer (default 8)')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-d', '--duration', type=int, help='Duration to run the tracer in seconds. Default is NULL (run indefinitely)')
    parser.add_argument('-f', '--flush_threshold', type=int, default=10000, help='Buffered flush threshold in array length (default 10000)')
    parser.add_argument('-s', '--split_threshold', type=int, default=3600 * 24, help='Split threshold in seconds (default 1 day)')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file=parse_args.bpf_file.strip(),
        page_cnt=parse_args.page_cnt,
        verbose=parse_args.verbose,
        duration=parse_args.duration,
        flush_threshold=parse_args.flush_threshold,
        split_threshold=parse_args.split_threshold
    )
    tracer.trace()
