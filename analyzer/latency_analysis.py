import matplotlib.pyplot as plt
import seaborn as sns
import json

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