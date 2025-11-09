#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging, must be new!')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('-au', '--auto-upload', action='store_true', help='Enable anonymization of process and file names')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=parse_args.verbose,
        anonymous=parse_args.anonimize,
        automatic_upload=parse_args.auto_upload,
    )
    tracer.trace()
