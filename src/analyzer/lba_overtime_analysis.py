import pandas as pd
import matplotlib.pyplot as plt
import json
from pathlib import Path

def lba_overtime_analysis(df_raw, output_dir):
    df = df_raw.copy()
    df['lba'] = pd.to_numeric(df['lba'], errors='coerce')  
    df = df[df['lba'].notna()] 
    if 'READ' not in df['op'].values and 'WRITE' not in df['op'].values:
        print("No READ/WRITE operations found for LBA analysis")
        return
    
    # Filter for READ and WRITE operations with LBA data
    io_df = df[df['op'].isin(['READ', 'WRITE']) & (df['lba'] > 0)].copy()
    
    if io_df.empty:
        print("No READ/WRITE operations with valid LBA information")
        return
    
    # Sort by timestamp to see progression over time
    io_df = io_df.sort_values('timestamp')
    
    # Create a visualization showing access patterns for top files
    top_files = io_df['filename'].value_counts().head(5).index.tolist()

    min_timestamp = None
    max_timestamp = None

    # Find the min and max timestamps for the x-axis limits
    for file in top_files:
        file_df = io_df[io_df['filename'] == file]
        if not file_df.empty:
            if min_timestamp is None or file_df['timestamp'].min() < min_timestamp:
                min_timestamp = file_df['timestamp'].min()
            if max_timestamp is None or file_df['timestamp'].max() > max_timestamp:
                max_timestamp = file_df['timestamp'].max()
    
    if top_files:
        plt.figure(figsize=(16, 10))
        
        for i, file in enumerate(top_files):
            file_df = io_df[io_df['filename'] == file]
            if not file_df.empty:
                plt.subplot(len(top_files), 1, i+1)
                
                # READ operations
                reads = file_df[file_df['op'] == 'READ']
                if not reads.empty:
                    plt.scatter(reads['timestamp'], reads['lba'], 
                                c='blue', label='READ', alpha=0.7, s=40)
                
                # WRITE operations
                writes = file_df[file_df['op'] == 'WRITE']
                if not writes.empty:
                    plt.scatter(writes['timestamp'], writes['lba'], 
                                c='red', label='WRITE', alpha=0.7, s=40)
                
                plt.title(f'LBA Access Pattern: {file}')
                plt.ylabel('LBA')
                plt.xlim(min_timestamp, max_timestamp)
                
                # Only show x-label on the bottom subplot
                if i == len(top_files) - 1:
                    plt.xlabel('Time')
                
                plt.grid(True, alpha=0.3)
                plt.legend()
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/top_files_lba_overtime.png")
    

    sequential_stats = {}
    
    for file in io_df['filename'].value_counts().head(10).index.unique():
        file_io = io_df[io_df['filename'] == file].sort_values('timestamp')
        
        if len(file_io) < 2:
            continue
            
        file_io.loc[:,'next_lba'] = file_io['lba'].shift(-1)
        file_io.loc[:,'lba_diff'] = file_io['next_lba'] - file_io['lba']

        sequential_count = len(file_io[(file_io['lba_diff'] > 0) & (file_io['lba_diff'] < 1000)])
        random_count = len(file_io) - sequential_count - 1  
        
        if sequential_count + random_count > 0:
            sequential_pct = sequential_count / (sequential_count + random_count) * 100
            sequential_stats[file] = {
                'sequential_ops': sequential_count,
                'random_ops': random_count,
                'sequential_percentage': sequential_pct
            }
    
    if sequential_stats:
        with open(f"{output_dir}/sequential_access_stats.json", 'w') as f:
            json.dump(sequential_stats, f, indent=4)
            
        # Create a bar chart showing sequential vs random percentages
        files = list(sequential_stats.keys())
        seq_percentages = [stats['sequential_percentage'] for stats in sequential_stats.values()]
        random_percentages = [100 - pct for pct in seq_percentages]
        
        plt.figure(figsize=(12, 6))
        bar_width = 0.35
        indices = range(len(files))
        
        plt.bar(indices, seq_percentages, bar_width, label='Sequential')
        plt.bar(indices, random_percentages, bar_width, 
                bottom=seq_percentages, label='Random')
        
        plt.xlabel('Files')
        plt.ylabel('Percentage')
        plt.title('Sequential vs Random Access by File')
        plt.xticks(indices, [Path(f).name for f in files], rotation=45, ha='right')
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/sequential_vs_random.png")