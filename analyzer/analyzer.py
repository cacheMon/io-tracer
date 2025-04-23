import numpy as np
import argparse
import json
from pathlib import Path
from log_parser import parse_trace_log
from time_series_analysis import time_series_analysis    
from heatmap_file_access import heatmap_file_access   
from latency_analysis import latency_analysis
from throughput_analysis import throughput_analysis
from operation_frequency_analysis import operation_frequency_analysis
from summary import generate_summary_stats



def main():
    parser = argparse.ArgumentParser(description='Analyze VFS trace logs')
    parser.add_argument('log_file', type=str, help='VFS trace log file to analyze')
    parser.add_argument('-o', '--output', type=str, default='vfs_analysis', help='Output directory for analysis results')
    args = parser.parse_args()
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    print(f"Analyzing trace file: {args.log_file}")
    print(f"Output directory: {output_dir}")
    
    df = parse_trace_log(args.log_file)
    
    if df.empty:
        print("No valid trace data found in the log file")
        return
    
    print(f"Parsed {len(df)} VFS operations")
    
    charts_dir = output_dir / "charts"
    charts_dir.mkdir(exist_ok=True)
    
    print("Generating time-series analysis...")
    time_series_analysis(df, charts_dir)
    
    print("Generating file access heatmaps...")
    heatmap_file_access(df, charts_dir)
    
    print("Analyzing latency distribution...")
    latency_analysis(df, charts_dir)
    
    print("Calculating throughput...")
    throughput_analysis(df, charts_dir)
    
    print("Analyzing operation frequency...")
    operation_frequency_analysis(df, charts_dir)
    
    print("Generating summary statistics...")
    generate_summary_stats(df, output_dir)
    
    print(f"Analysis complete. Results saved to {output_dir}/")
    print(f"Charts can be found in {charts_dir}/")

if __name__ == "__main__":
    main()