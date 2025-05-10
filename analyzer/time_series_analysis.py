import matplotlib.pyplot as plt
import pandas as pd

def time_series_analysis(df, output_dir):
    plt.figure(figsize=(12, 6))
    
    time_series = df.set_index('timestamp')
    ops_by_time = time_series.groupby([pd.Grouper(freq='1s'), 'op']).size().unstack().fillna(0)
    
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
            read_cumsum = read_df.resample('1s')['size'].sum().cumsum()
            
        if not write_df.empty:
            write_df.set_index('timestamp', inplace=True)
            write_cumsum = write_df.resample('1s')['size'].sum().cumsum()
        
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