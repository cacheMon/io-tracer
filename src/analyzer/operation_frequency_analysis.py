import matplotlib.pyplot as plt
import pandas as pd

def operation_frequency_analysis(df, output_dir):
    filtered_op = df['op'][df['op'] != '[none]']
    filtered_op_blk = df['op_blk'][df['op_blk'] != '[none]']

    op_combined = pd.concat([filtered_op, filtered_op_blk], ignore_index=True)
    op_counts = op_combined.value_counts()
    
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