#!/usr/bin/env python3
"""
IO Tracer - A Linux I/O syscall tracing utility.

This module serves as the entry point for the IO Tracer application, which
traces file system, block device, cache, and network I/O operations on Linux
systems using eBPF/BPF technology.

Usage:
    python iotrc.py [OPTIONS]

Options:
    -o, --output DIRECTORY    Output directory for logging (default: ./result)
    -v, --verbose             Print verbose output
    -a, --anonimize           Enable anonymization of process and file names
    --dev                     Developer mode with extra logs and checks
    --computer-id             Print this machine ID and exit
    --reward                  Show your reward code (unlocked after uploading traces)

Examples:
    # Run with default settings
    python iotrc.py

    # Run with verbose output and custom output directory
    python iotrc.py -v -o /tmp/traces

    # Run in developer mode
    python iotrc.py --dev

    # Print machine ID
    python iotrc.py --computer-id

    # Check reward status
    python iotrc.py --reward
"""

import argparse
import os
import resource
import sys

from src.tracer.IOTracer import IOTracer
from src.utility.utils import capture_machine_id, get_reward_code, is_reward_unlocked


def maximize_fd_limit():
    """Attempt to maximize the file descriptor open limit."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 1048576
        if hard != resource.RLIM_INFINITY:
            target = min(target, hard)
        # Sudo often drops the soft limit to 1024. Elevate it back up.
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: IO Tracer must be run with sudo or as root.")
        sys.exit(1)
        
    maximize_fd_limit()
    app_version = "vRelease"
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('--dev', action='store_true', help='Developer mode with extra logs and checks')
    parser.add_argument('--computer-id', action='store_true', help='Print this machine ID and exit')
    parser.add_argument('--reward', action='store_true', help='Show your reward code (unlocked after uploading traces)')

    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()
    
    # Handle --computer-id flag: print machine ID and exit
    if parse_args.computer_id:
        print(f"Here is your computer ID: {capture_machine_id().upper()}")
        exit(0)
    
    # Handle --reward flag: show reward code if available
    if parse_args.reward:
        reward_code = get_reward_code()
        if reward_code:
            print(f"Your Prolific submissions code: {reward_code}")
        else:
            print("Reward not yet unlocked. Upload at least one trace to complete your submission!")
        exit(0)
    

    # Initialize and start the IO tracer
    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=parse_args.verbose,
        anonymous=parse_args.anonimize,
        automatic_upload=not parse_args.dev,
        developer_mode=parse_args.dev,
        version=app_version,
    )
    tracer.trace()
