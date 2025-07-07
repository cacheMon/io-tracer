import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
from pathlib import Path

def heatmap_file_access(df_raw, output_dir):
    df = df_raw.copy()
    df['lba'] = pd.to_numeric(df['lba'], errors='coerce')  
    df = df[df['lba'].notna()] 
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
            if len(file_df) < 5:  # skip if not enough data points
                continue
                
            max_lba = file_df['lba'].max()
            if max_lba <= 0:
                continue
                
            bins = np.linspace(0, max_lba, 10)
            file_df = io_df[io_df['filename'] == file].copy() 
            file_df['lba_bin'] = pd.cut(file_df['lba'], bins)
            
            lba_heatmap = pd.crosstab(file_df['lba_bin'], file_df['op'])
            
            plt.figure(figsize=(12, 6))
            sns.heatmap(lba_heatmap, annot=True, cmap='viridis', fmt='d')
            plt.title(f'LBA Access Patterns for {file}')
            plt.xlabel('Operation Type')
            plt.ylabel('LBA Range')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/lba_access_{Path(file).name.replace('/', '_')}.png")