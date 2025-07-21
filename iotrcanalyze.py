#!/usr/bin/env python3

import argparse
from src.analyzer.analyzer import IOTraceAnalyzer
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Analyze I/O tracing data optimized for workload comparison')
    parser.add_argument('-rf', '--raw-file', type=str, help='Compressed raw file to parse', required=True)
    parser.add_argument('-n', '--name', type=str, help='Workload name for identification', default=None)
    parser.add_argument('-o', '--output', type=str, help='Output directory', default='.')
    parser.add_argument('--all', action='store_true', help='Create all charts and reports')
    
    args = parser.parse_args()
    
    analyzer = IOTraceAnalyzer(args.raw_file, args.name)
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    analyzer.export_workload_analysis(output_dir)
   

if __name__ == "__main__":
    main()