import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
from pathlib import Path

def heatmap_file_access(df_raw, output_dir):
    df = df_raw.copy()
    df['lba'] = pd.to_numeric(df['lba'], errors='coerce')  
    df = df[df['lba'].notna()] 

    io_df = df.copy()    
    io_vfs_df = io_df[io_df['op'] != '[none]']
    io_blk_df = io_df[io_df['op_blk'] != '[none]']

    if len(io_vfs_df) == 0 and len(io_blk_df) == 0:
        print("No valid operations found after filtering out '[none]' values")
        return
    top_files = io_df['filename'].value_counts().head(10).index.tolist()
    
    if not top_files:
        print("No files with sufficient access patterns for heatmap")
        return

    file_access_vfs = io_vfs_df[io_vfs_df['filename'].isin(top_files)]

    heatmap_data = pd.crosstab(file_access_vfs['filename'], file_access_vfs['op'])
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(heatmap_data, annot=True, cmap='viridis', fmt='d')
    plt.title('File Access Patterns by Block Operation Type')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/file_access_heatmap_vfs.png")
    plt.close()

    file_access_blk = io_blk_df[io_blk_df['filename'].isin(top_files)]

    heatmap_data = pd.crosstab(file_access_blk['filename'], file_access_blk['op_blk'])

    plt.figure(figsize=(10, 8))
    sns.heatmap(heatmap_data, annot=True, cmap='viridis', fmt='d')
    plt.title('File Access Patterns by Operation Type')
    plt.tight_layout()
    plt.savefig(f"{output_dir}/file_access_heatmap_blk.png")
    plt.close()
    
    if io_df['lba'].sum() > 0:
        for file in top_files[:5]:
            file_df = io_df[io_df['filename'] == file]
            file_vfs_df = file_df.copy()
            file_vfs_df = file_vfs_df[file_vfs_df['op'] != '[none]']
            if len(file_vfs_df) < 5:  # skip if not enough data points
                continue
                
            max_lba = file_vfs_df['lba'].max()
            if max_lba <= 0:
                continue
                
            bins = np.linspace(0, max_lba, 10)
            file_vfs_df = io_df[io_df['filename'] == file].copy() 
            file_vfs_df['lba_bin'] = pd.cut(file_vfs_df['lba'], bins)
            
            lba_heatmap = pd.crosstab(file_vfs_df['lba_bin'], file_vfs_df['op'])
            
            plt.figure(figsize=(12, 6))
            sns.heatmap(lba_heatmap, annot=True, cmap='viridis', fmt='d')

            plt.title(f'LBA Access Patterns for {file}')
            plt.xlabel('Operation Type')
            plt.ylabel('LBA Range')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/lba_access_vfs_{Path(file).name.replace('/', '_')}.png")
            plt.close()

        for file in top_files[:5]:
            file_df = io_df[io_df['filename'] == file]
            
            file_blk_df = file_df.copy()
            file_blk_df = file_blk_df[file_blk_df['op_blk'] != '[none]']
            if len(file_blk_df) < 5:  # skip if not enough data points
                continue

            max_lba = file_blk_df['lba'].max()
            if max_lba <= 0:
                continue
                
            bins = np.linspace(0, max_lba, 10)
            file_blk_df = io_df[io_df['filename'] == file].copy()
            file_blk_df['lba_bin'] = pd.cut(file_blk_df['lba'], bins)

            lba_heatmap = pd.crosstab(file_blk_df['lba_bin'], file_blk_df['op_blk'])

            plt.figure(figsize=(12, 6))
            sns.heatmap(lba_heatmap, annot=True, cmap='viridis', fmt='d')

            plt.title(f'LBA Access Patterns for {file}')
            plt.xlabel('Operation Type')
            plt.ylabel('LBA Range')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/lba_access_blk_{Path(file).name.replace('/', '_')}.png")