#!/usr/bin/env python3

import argparse
import os
from src.tracer.IOTracer import IOTracer

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace IO syscalls with periodic compression support')
    
    parser.add_argument('-o', '--output', type=str, default="./result", 
                       help='Output Directory for logging')
    parser.add_argument('-b', '--bpf-file', type=str, default='./src/tracer/prober/prober.c', 
                       help='BPF C source file path')
    parser.add_argument('-p', '--page-cnt', type=int, default=8, 
                       help='Number of pages for perf buffer (default 8)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Print verbose output')
    parser.add_argument('-d', '--duration', type=int, 
                       help='Duration to run the tracer in seconds. Default is NULL (run indefinitely)')
    parser.add_argument('-a', '--anonimize', action='store_true', 
                       help='Enable anonymization of process and file names')
    
    parser.add_argument('-s', '--split_threshold', type=int, default=60*5, 
                       help='File rotation threshold in seconds (default 30s)')
    parser.add_argument('-uc','--uncompressed', action='store_true', 
                       help='Keep uncompressed files after tracing')
    
    parser.add_argument('--enable-compression', action='store_true', default=True,
                       help='Enable periodic compression of trace files (default: enabled)')
    parser.add_argument('--disable-compression', action='store_true',
                       help='Disable periodic compression of trace files')
    parser.add_argument('--compression-interval', type=int, default=60*60,
                       help='Interval between compression runs in seconds (default 3600 = 1 hour)')
    parser.add_argument('--compression-level', type=int, default=6, choices=range(1, 10),
                       help='Gzip compression level 1-9 (1=fastest, 9=best compression, default 6)')
    
    parser.add_argument('--cache-sample-rate', type=int, default=1,
                       help='Cache event sampling rate (1=all events, 10=every 10th event, etc.)')
    
    parser.add_argument('--max-file-size', type=int, default=100,
                       help='Maximum file size in MB before rotation (default 100MB)')
    
    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()
    
    enable_compression = parse_args.enable_compression and not parse_args.disable_compression
    
    if parse_args.compression_interval < 60:
        print("Warning: Compression interval less than 60 seconds may impact performance")
    
    if parse_args.split_threshold < 60:
        print("Warning: File rotation threshold less than 60 seconds will create many small files")
    
    print("=" * 60)
    print("IO Tracer Configuration:")
    print(f"  Output directory: {output_dir}")
    print(f"  Duration: {parse_args.duration if parse_args.duration else 'Indefinite'}")
    print(f"  Verbose: {parse_args.verbose}")
    print(f"  Anonymous mode: {parse_args.anonimize}")
    print(f"  File rotation: every {parse_args.split_threshold} seconds")
    print(f"  Compression: {'Enabled' if enable_compression else 'Disabled'}")
    if enable_compression:
        print(f"    - Interval: {parse_args.compression_interval} seconds")
        print(f"    - Level: {parse_args.compression_level}")
    print(f"  Cache sampling: 1:{parse_args.cache_sample_rate}")
    print(f"  Keep uncompressed: {parse_args.uncompressed}")
    print("=" * 60)
    
    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file=parse_args.bpf_file.strip(),
        page_cnt=parse_args.page_cnt,
        verbose=parse_args.verbose,
        duration=parse_args.duration,
        split_threshold=parse_args.split_threshold,
        anonymous=parse_args.anonimize,
        is_uncompressed=parse_args.uncompressed,
        enable_compression=enable_compression,
        compression_interval=parse_args.compression_interval,
        compression_level=parse_args.compression_level,
        cache_sample_rate=parse_args.cache_sample_rate
    )
    
    tracer.trace()