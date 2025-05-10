import numpy as np
import json

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