import matplotlib.pyplot as plt
import json

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