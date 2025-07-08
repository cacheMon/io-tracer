import matplotlib.pyplot as plt
import json

def throughput_analysis(df, output_dir):
    io_df = df.copy()
    
    io_df['op'] = io_df['op'].replace('[none]', None)
    io_df['op_blk'] = io_df['op_blk'].replace('[none]', None)
    
    io_df['operation'] = io_df['op'].fillna(io_df['op_blk'])
    
    io_df = io_df[io_df['operation'].notna()]
    
    if io_df.empty:
        print("No valid operations found for throughput analysis")
        return
    
    io_df['size'] = io_df['size'].astype('float64')
    print(f"Converted size column to float64 to prevent overflow")
    
    total_duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
    
    if total_duration > 86400: 
        freq = '1H'
        freq_label = 'Hour'
    elif total_duration > 3600:  
        freq = '10min'
        freq_label = '10min'
    else:
        freq = '1s'
        freq_label = 'Second'
    
    io_df.loc[:,'timestamp_floor'] = io_df['timestamp'].dt.floor(freq)
    
    throughput = io_df.groupby(['timestamp_floor', 'operation'])['size'].sum().unstack().fillna(0)
    
    throughput = throughput / 1024
    
    marker = 'o' if len(throughput) < 500 else None
    
    throughput.plot(kind='line', marker=marker, figsize=(16, 6))
    plt.title(f'I/O Throughput Over Time ({freq} intervals)')
    plt.xlabel('Time')
    plt.ylabel(f'Throughput (KB/{freq_label.lower()})')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{output_dir}/throughput.png")
    plt.close()
    
    avg_throughput = {}
    for op in throughput.columns:
        avg_throughput[op] = throughput[op].mean()
    
    with open(f"{output_dir}/throughput_stats.json", 'w') as f:
        json.dump(avg_throughput, f, indent=4)