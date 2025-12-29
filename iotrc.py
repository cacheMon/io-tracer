#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer
from src.utility.utils import capture_machine_id

if __name__ == "__main__":
    app_version = "vRelease"
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('-l', '--local-only', action='store_true', help='Disable automatic upload of logs, save the trace locally')
    parser.add_argument('--dev', action='store_true', help='Developer mode with extra logs and checks')
    parser.add_argument('--computer-id', action='store_true', help='Print this machine ID and exit')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()
    
    is_upload = not parse_args.local_only
    
    if parse_args.computer_id:
        print(f"Here is your computer ID: {capture_machine_id().upper()}")
        exit(0)
    
    if is_upload:
        print("[*] Automatic upload enabled, logs will be uploaded during tracing.")
    else:
        print("[*] Local only mode enabled, automatic upload disabled.")

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=parse_args.verbose,
        anonymous=parse_args.anonimize,
        automatic_upload=is_upload,
        developer_mode=parse_args.dev,
        version=app_version,
    )
    tracer.trace()
