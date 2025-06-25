#!/usr/bin/env python3

import argparse

from src.tracer.BlockToFS import BlockToFS

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace VFS syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for mapper')
    parser.add_argument('-vfs', '--vfs-log', type=str, help='vfs log path')
    parser.add_argument('-blk', '--blk-log', type=str, help='block log path')
    parser.add_argument('-tw', '--time-window', type=int, default=5_000_000, help='Time window for matching PIDs (default 5_000_000 ns)')


    parse_args = parser.parse_args()
    output_dir = parse_args.output.strip()
    vfs_log = parse_args.vfs_log.strip()
    blk_log = parse_args.blk_log.strip()
    time_window = parse_args.time_window

    BlockToFS(block_log=blk_log, vfs_log=vfs_log, output_dir=output_dir, time_window=time_window).run()
