#!/usr/bin/env python3

import argparse

from tracer.IOTracer import IOTracer

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace VFS syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging')
    parser.add_argument('-b', '--bpf-file', type=str, default='./tracer/vfs_prober.c', help='BPF C source file path')
    parser.add_argument('-p', '--page-cnt', type=int, default=8, help='Number of pages for perf buffer (default 8)')
    parser.add_argument('-a', '--analyze', type=bool, help='Run analyzer on completion')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-d', '--duration', type=int, default=10, help='Duration to run the tracer in seconds (default 10)')

    tracer = IOTracer(
        output_dir=parser.parse_args().output.strip(),
        bpf_file=parser.parse_args().bpf_file.strip(),
        page_cnt=parser.parse_args().page_cnt,
        analyze=parser.parse_args().analyze,
        verbose=parser.parse_args().verbose,
        duration=parser.parse_args().duration
    )
    # tracer.debug()
    tracer.trace()
