#!/usr/bin/python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import re
import argparse
from datetime import datetime
from pathlib import Path
import json

LOG_PATTERN = r'\[([\d:\.]+)\] (\w+): PID (\d+) \(([^)]+)\): file \'([^\']*)\' \(inode: (\d+)\)(, size: (\d+) bytes, LBA: (\d+),)? flags: (.+)'

def parse_trace_log(log_file):
    data = []
    
    with open(log_file, 'r') as f:
        for line in f:
            match = re.match(LOG_PATTERN, line.strip())
            if match:
                timestamp_str = match.group(1)
                timestamp = datetime.strptime(timestamp_str, '%H:%M:%S.%f')
                
                op = match.group(2)
                pid = int(match.group(3))
                comm = match.group(4)
                filename = match.group(5)
                inode = int(match.group(6))
                
                # For READ/WRITE operations
                size = int(match.group(8)) if match.group(8) else 0
                lba = int(match.group(9)) if match.group(9) else 0
                flags = match.group(10)
                
                data.append({
                    'timestamp': timestamp,
                    'op': op,
                    'pid': pid,
                    'comm': comm,
                    'filename': filename,
                    'inode': inode,
                    'size': size,
                    'lba': lba,
                    'flags': flags
                })
    
    return pd.DataFrame(data)

def time_series_analysis(df, output_dir):
    plt.figure(figsize=(12, 6))
    
    time_series = df.set_index('timestamp')
    ops_by_time = time_series.groupby([pd.Grouper(freq='1S'), 'op']).size().unstack().fillna(0)
    
    # Plot
    ax = ops_by_time.plot(kind='line', marker='o')
    plt.title('I/O Operations Over Time')
    plt.xlabel('Time')
    plt.ylabel('Number of Operations')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/time_series_operations.png")
    
    if 'READ' in df['op'].values or 'WRITE' in df['op'].values:
        read_df = df[df['op'] == 'READ'].copy()
        write_df = df[df['op'] == 'WRITE'].copy()
        
        if not read_df.empty:
            read_df.set_index('timestamp', inplace=True)
            read_cumsum = read_df.resample('1S')['size'].sum().cumsum()
            
        if not write_df.empty:
            write_df.set_index('timestamp', inplace=True)
            write_cumsum = write_df.resample('1S')['size'].sum().cumsum()
        
        plt.figure(figsize=(12, 6))
        if not read_df.empty:
            plt.plot(read_cumsum.index, read_cumsum / (1024*1024), marker='o', label='Read (MB)')
        if not write_df.empty:
            plt.plot(write_cumsum.index, write_cumsum / (1024*1024), marker='x', label='Write (MB)')
        
        plt.title('Cumulative I/O Size Over Time')
        plt.xlabel('Time')
        plt.ylabel('Cumulative Size (MB)')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/cumulative_io_size.png")

def heatmap_file_access(df, output_dir):
    if 'READ' not in df['op'].values and 'WRITE' not in df['op'].values:
        print("No READ/WRITE operations found for heatmap")
        return
    
    io_df = df[df['op'].isin(['READ', 'WRITE'])]
    
    top_files = io_df['filename'].value_counts().head(10).index.tolist()
    
    if not top_files:
        print("No files with sufficient access patterns for heatmap")
        return
    
    file_access = io_df[io_df['filename'].isin(top_files)]
    
    heatmap_data = pd.crosstab(file_access['filename'], file_access['op'])
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(heatmap_data, annot=True, cmap='viridis', fmt='d')
    plt.title('File Access Patterns by Operation Type')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/file_access_heatmap.png")
    
    if io_df['lba'].sum() > 0:
        for file in top_files[:5]:
            file_df = io_df[io_df['filename'] == file]
            if len(file_df) < 5:  # Skip if not enough data points
                continue
                
            max_lba = file_df['lba'].max()
            if max_lba <= 0:
                continue
                
            bins = np.linspace(0, max_lba, 10)
            file_df['lba_bin'] = pd.cut(file_df['lba'], bins)
            
            lba_heatmap = pd.crosstab(file_df['lba_bin'], file_df['op'])
            
            plt.figure(figsize=(12, 6))
            sns.heatmap(lba_heatmap, annot=True, cmap='viridis', fmt='d')
            plt.title(f'LBA Access Patterns for {file}')
            plt.xlabel('Operation Type')
            plt.ylabel('LBA Range')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/lba_access_{Path(file).name.replace('/', '_')}.png")

def latency_analysis(df, output_dir):
    if len(df) <= 1:
        print("Not enough data points for latency analysis")
        return
        
    df = df.sort_values('timestamp')
    df['next_timestamp'] = df['timestamp'].shift(-1)
    df['latency_ms'] = (df['next_timestamp'] - df['timestamp']).dt.total_seconds() * 1000
    
    grouped = df.groupby('op')
    
    plt.figure(figsize=(12, 6))
    
    for op_type, group in grouped:
        latencies = group['latency_ms'].dropna()
        if len(latencies) > 0:
            sns.histplot(latencies, kde=True, label=op_type, alpha=0.5)
    
    plt.title('Latency Distribution by Operation Type')
    plt.xlabel('Latency (ms)')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/latency_distribution.png")
    
    stats = {}
    for op_type, group in grouped:
        latencies = group['latency_ms'].dropna()
        if len(latencies) > 0:
            stats[op_type] = {
                'mean_ms': latencies.mean(),
                'median_ms': latencies.median(),
                'p95_ms': latencies.quantile(0.95),
                'p99_ms': latencies.quantile(0.99),
                'min_ms': latencies.min(),
                'max_ms': latencies.max()
            }
    
    with open(f"{output_dir}/latency_stats.json", 'w') as f:
        json.dump(stats, f, indent=4)

def throughput_analysis(df, output_dir):
    if 'READ' not in df['op'].values and 'WRITE' not in df['op'].values:
        print("No READ/WRITE operations found for throughput analysis")
        return
    
    io_df = df[df['op'].isin(['READ', 'WRITE'])]
    
    if io_df.empty:
        print("No READ/WRITE operations with size information")
        return
    
    io_df['timestamp_second'] = io_df['timestamp'].dt.floor('S')
    throughput = io_df.groupby(['timestamp_second', 'op'])['size'].sum().unstack().fillna(0)
    
    throughput = throughput / 1024
    
    plt.figure(figsize=(12, 6))
    throughput.plot(kind='line', marker='o')
    plt.title('I/O Throughput Over Time')
    plt.xlabel('Time')
    plt.ylabel('Throughput (KB/s)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{output_dir}/throughput.png")
    
    avg_throughput = {}
    for op in throughput.columns:
        avg_throughput[op] = throughput[op].mean()
    
    with open(f"{output_dir}/throughput_stats.json", 'w') as f:
        json.dump(avg_throughput, f, indent=4)

def operation_frequency_analysis(df, output_dir):
    op_counts = df['op'].value_counts()
    
    plt.figure(figsize=(10, 6))
    op_counts.plot(kind='bar')
    plt.title('Operation Frequency')
    plt.xlabel('Operation Type')
    plt.ylabel('Count')
    plt.grid(True, axis='y')
    for i, v in enumerate(op_counts):
        plt.text(i, v + 0.1, str(v), ha='center')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/operation_frequency.png")
    
    proc_counts = df.groupby(['pid', 'comm'])['op'].count().sort_values(ascending=False).head(10)
    
    plt.figure(figsize=(12, 6))
    proc_counts.plot(kind='bar')
    plt.title('Top 10 Processes by Operation Count')
    plt.xlabel('Process (PID, Command)')
    plt.ylabel('Operation Count')
    plt.grid(True, axis='y')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/process_frequency.png")
    
    file_counts = df['filename'].value_counts().head(10)
    
    plt.figure(figsize=(12, 6))
    file_counts.plot(kind='bar')
    plt.title('Top 10 Files by Operation Count')
    plt.xlabel('Filename')
    plt.ylabel('Operation Count')
    plt.grid(True, axis='y')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/file_frequency.png")

def generate_summary_stats(df, output_dir):
    def convert_to_serializable(obj):
        if isinstance(obj, (np.integer, np.int64)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj
    
    summary = {
        "total_operations": int(len(df)),
        "operations_by_type": {k: int(v) for k, v in df['op'].value_counts().to_dict().items()},
        "unique_files": int(df['filename'].nunique()),
        "unique_processes": int(df['pid'].nunique())
    }
    
    read_df = df[df['op'] == 'READ']
    write_df = df[df['op'] == 'WRITE']
    
    if not read_df.empty:
        summary["read_stats"] = {
            "total_reads": int(len(read_df)),
            "total_read_bytes": int(read_df['size'].sum()),
            "avg_read_size": float(read_df['size'].mean()),
            "max_read_size": int(read_df['size'].max())
        }
    
    if not write_df.empty:
        summary["write_stats"] = {
            "total_writes": int(len(write_df)),
            "total_write_bytes": int(write_df['size'].sum()),
            "avg_write_size": float(write_df['size'].mean()),
            "max_write_size": int(write_df['size'].max())
        }
    
    top_files = df['filename'].value_counts().head(10).to_dict()
    summary["top_files"] = {k: int(v) for k, v in top_files.items()}
    
    top_processes = df.groupby('comm')['op'].count().sort_values(ascending=False).head(10).to_dict()
    summary["top_processes"] = {k: int(v) for k, v in top_processes.items()}
    
    with open(f"{output_dir}/summary_stats.json", 'w') as f:
        json.dump(summary, f, indent=4)
    
    with open(f"{output_dir}/summary_stats.txt", 'w') as f:
        f.write("VFS TRACE ANALYSIS SUMMARY\n")
        f.write("==========================\n\n")
        f.write(f"Total Operations: {summary['total_operations']}\n")
        f.write("\nOperations by Type:\n")
        for op, count in summary.get('operations_by_type', {}).items():
            f.write(f"  {op}: {count}\n")
        
        f.write(f"\nUnique Files: {summary['unique_files']}\n")
        f.write(f"Unique Processes: {summary['unique_processes']}\n")
        
        if 'read_stats' in summary:
            rs = summary['read_stats']
            f.write("\nRead Statistics:\n")
            f.write(f"  Total Reads: {rs['total_reads']}\n")
            f.write(f"  Total Read Bytes: {rs['total_read_bytes']} ({rs['total_read_bytes']/1024/1024:.2f} MB)\n")
            f.write(f"  Average Read Size: {rs['avg_read_size']:.2f} bytes\n")
            f.write(f"  Max Read Size: {rs['max_read_size']} bytes\n")
        
        if 'write_stats' in summary:
            ws = summary['write_stats']
            f.write("\nWrite Statistics:\n")
            f.write(f"  Total Writes: {ws['total_writes']}\n")
            f.write(f"  Total Write Bytes: {ws['total_write_bytes']} ({ws['total_write_bytes']/1024/1024:.2f} MB)\n")
            f.write(f"  Average Write Size: {ws['avg_write_size']:.2f} bytes\n")
            f.write(f"  Max Write Size: {ws['max_write_size']} bytes\n")
        
        f.write("\nTop 10 Files by Operation Count:\n")
        for i, (file, count) in enumerate(summary.get('top_files', {}).items(), 1):
            f.write(f"  {i}. {file}: {count}\n")
        
        f.write("\nTop 10 Processes by Operation Count:\n")
        for i, (proc, count) in enumerate(summary.get('top_processes', {}).items(), 1):
            f.write(f"  {i}. {proc}: {count}\n")

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