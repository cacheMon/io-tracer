#!/usr/bin/env python3

import argparse

from src.tracer.BlockToFS import BlockToFS

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse block and vfs logs to match PIDs')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for mapper')
    parser.add_argument('-rf', '--raw-file', type=str, help='zipped raw file to parse', required=True)
    parser.add_argument('-tw', '--time-window', type=int, default=5_000_000, help='Time window for matching PIDs (default 5_000_000 ns)')


    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()
    raw_file = parse_args.raw_file.strip()
    time_window = parse_args.time_window

    BlockToFS(raw_file = raw_file, output_dir=output_dir, time_window=time_window).run()
