from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def time_series_analysis(df_raw, output_dir):
    # df = generate_large_io_data()
    df = df_raw.copy()
    total_duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
    
    if total_duration > 86400:
        freq = '1H'
    elif total_duration > 3600:  
        freq = '1min'  
    else:
        freq = '1s'
    
    time_series = df.set_index('timestamp')
    ops_by_time = time_series.groupby([pd.Grouper(freq=freq), 'op']).size().unstack().fillna(0)
    
    # Remove markers for large datasets
    marker = 'o' if len(ops_by_time) < 1000 else None
    
    ax = ops_by_time.plot(kind='line', marker=marker, figsize=(16, 6))
    plt.title(f'I/O Operations Over Time ({freq} intervals)')
    plt.xlabel('Time')
    plt.ylabel('Number of Operations')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/time_series_operations.png", dpi=150)  # Lower DPI for smaller files
    plt.close()
    
    if 'READ' in df['op'].values or 'WRITE' in df['op'].values:
        if total_duration > 86400: 
            freq = '1H'
        elif total_duration > 3600:
            freq = '10min'
        else:
            freq = '10s'
        
        read_df = df[df['op'] == 'READ'].copy()
        write_df = df[df['op'] == 'WRITE'].copy()
        
        if not read_df.empty:
            read_df.set_index('timestamp', inplace=True)
            read_cumsum = read_df.resample(freq)['size'].sum().cumsum()
            
        if not write_df.empty:
            write_df.set_index('timestamp', inplace=True)
            write_cumsum = write_df.resample(freq)['size'].sum().cumsum()
        
        plt.figure(figsize=(18, 6))
        
        # Remove markers for large datasets
        marker_read = 'o' if len(read_cumsum) < 500 else None if not read_df.empty else None
        marker_write = 'x' if len(write_cumsum) < 500 else None if not write_df.empty else None
        
        if not read_df.empty:
            plt.plot(read_cumsum.index, read_cumsum / (1024*1024), marker=marker_read, label='Read (MB)')
        if not write_df.empty:
            plt.plot(write_cumsum.index, write_cumsum / (1024*1024), marker=marker_write, label='Write (MB)')
        
        plt.title(f'Cumulative I/O Size Over Time ({freq} intervals)')
        plt.xlabel('Time')
        plt.ylabel('Cumulative Size (MB)')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/cumulative_io_size.png")
        plt.close()