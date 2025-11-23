#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer

if __name__ == "__main__":
    app_version = "v1.0.2"
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging, must be new!')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('-au', '--auto-upload', action='store_true', help='Enable automatic upload of logs')
    parser.add_argument('-s', '--server-mode', action='store_true', help='Optimized for higher throughput in server environments')
    parser.add_argument('--dev', action='store_true', help='Developer mode with extra logs and checks')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=parse_args.verbose,
        anonymous=parse_args.anonimize,
        automatic_upload=parse_args.auto_upload,
        developer_mode=parse_args.dev,
        version=app_version,
    )
    tracer.trace()
