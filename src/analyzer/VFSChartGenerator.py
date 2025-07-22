import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional


class VFSChartGenerator:    
    def __init__(self, workload_name: str, vfs_df: pd.DataFrame):
        self.workload_name = workload_name
        self.vfs_df = vfs_df

    def create_vfs_operation_types_chart(self, save_path: str = None):
        if self.vfs_df is None:
            print("VFS data not available, skipping VFS operation types chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        vfs_ops = self.vfs_df['op_name'].value_counts()
        colors = plt.cm.Set2(np.linspace(0, 1, len(vfs_ops)))
        
        bars = ax.bar(vfs_ops.index, vfs_ops.values, color=colors, edgecolor='black')
        ax.set_xlabel('VFS Operation Type', fontsize=12, fontweight='bold')
        ax.set_ylabel('Number of Operations', fontsize=12, fontweight='bold')
        ax.set_title(f'VFS Operation Types Distribution - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.tick_params(axis='x', rotation=45)
        ax.grid(True, alpha=0.3)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS operation types chart saved to: {save_path}")
        
        return fig

    def create_file_access_chart(self, save_path: str = None):
        if self.vfs_df is None:
            print("VFS data not available, skipping file access chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        file_access = self.vfs_df['filename'].value_counts().head(15)
        
        bars = ax.barh(range(len(file_access)), file_access.values, color='lightgreen', edgecolor='darkgreen')
        ax.set_xlabel('Number of Accesses', fontsize=12, fontweight='bold')
        ax.set_ylabel('Files', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 15 Most Accessed Files - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_yticks(range(len(file_access)))
        
        truncated_names = [name[:40] + '...' if len(name) > 40 else name for name in file_access.index]
        ax.set_yticklabels(truncated_names)
        ax.invert_yaxis() 
        ax.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                    f'{int(width):,}', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"File access chart saved to: {save_path}")
        
        return fig

    def create_vfs_open_flags_chart(self, save_path: str = None):
        if self.vfs_df is None or 'flags_str' not in self.vfs_df.columns:
            print("VFS data with open flags not available, skipping chart.")
            return None

        open_ops = self.vfs_df[self.vfs_df['op_name'] == 'OPEN'].dropna(subset=['flags_str'])
        
        if open_ops.empty:
            print("No 'OPEN' operations with flags found in VFS data.")
            return None
        
        flag_counts = open_ops['flags_str'].str.split('|').explode().value_counts().head(15)

        if flag_counts.empty:
            print("Could not parse any open flags from the VFS data.")
            return None

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        bars = ax.bar(flag_counts.index, flag_counts.values, color='teal', edgecolor='black')
        ax.set_xlabel('File Open Flag', fontsize=12, fontweight='bold')
        ax.set_ylabel('Frequency of Use', fontsize=12, fontweight='bold')
        ax.set_title(f'VFS File Open Flag Frequency - {self.workload_name}', 
                    fontsize=16, fontweight='bold')
        ax.tick_params(axis='x', rotation=45, ha='right')
        ax.grid(True, axis='y', linestyle='--', alpha=0.6)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height, f'{int(height):,}',
                    ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS open flags chart saved to: {save_path}")
            
        return fig

    def create_vfs_iops_chart(self, save_path: str = None):
        if self.vfs_df is None:
            print("VFS data not available, skipping VFS IOPS chart.")
            return None

        fig, ax = plt.subplots(1, 1, figsize=(16, 8))

        duration = (self.vfs_df['timestamp'].max() - self.vfs_df['timestamp'].min()) / 1e9
        if duration > 3600: 
            time_window = '1min'  
        elif duration > 300:
            time_window = '10s'
        else:
            time_window = '1s'

        window_seconds = pd.Timedelta(time_window).total_seconds()
        vfs_iops = self.vfs_df.groupby(pd.Grouper(key='datetime', freq=time_window))['op_name'].count() / window_seconds
        
        ax.plot(vfs_iops.index, vfs_iops.values, color='darkorchid', linewidth=2, alpha=0.8)
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('VFS Operations Per Second (IOPS)', fontsize=12, fontweight='bold')
        ax.set_title(f'VFS IOPS Over Time ({time_window} windows) - {self.workload_name}', 
                    fontsize=16, fontweight='bold')
        ax.grid(True, linestyle='--', alpha=0.6)
        
        avg_iops = vfs_iops.mean()
        ax.axhline(y=avg_iops, color='red', linestyle='--', 
                label=f'Average: {avg_iops:.1f} VFS IOPS')
        ax.legend(fontsize=12)
        
        for tick in ax.get_xticklabels():
            tick.set_rotation(45)

        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS IOPS chart saved to: {save_path}")
            
        return fig

    def create_vfs_rw_size_distribution_chart(self, save_path: str = None):
        if self.vfs_df is None or 'size_val' not in self.vfs_df.columns:
            print("VFS data with size values not available, skipping chart.")
            return None

        rw_ops = self.vfs_df[
            self.vfs_df['op_name'].isin(['READ', 'WRITE']) & (self.vfs_df['size_val'] > 0)
        ].copy()

        if rw_ops.empty:
            print("No VFS READ or WRITE operations with positive size found.")
            return None

        rw_ops['size_log10'] = np.log10(rw_ops['size_val'])
        
        rw_ops['op_name'] = rw_ops['op_name'].astype(str)

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))

        color_map = {'READ': 'skyblue', 'WRITE': 'salmon'}
        sns.boxenplot(
            x='op_name', 
            y='size_log10', 
            hue='op_name',              
            data=rw_ops, 
            ax=ax,
            palette=color_map,          
            legend=False
        )

        y_ticks = np.log10([4096, 16384, 65536, 262144, 1048576, 4194304])
        y_labels = ['4KB', '16KB', '64KB', '256KB', '1MB', '4MB']
        ax.set_yticks(y_ticks)
        ax.set_yticklabels(y_labels)

        ax.set_xlabel('VFS Operation', fontsize=12, fontweight='bold')
        ax.set_ylabel('I/O Size (Log Scale)', fontsize=12, fontweight='bold')
        ax.set_title(f'Distribution of VFS Read/Write Sizes - {self.workload_name}', 
                    fontsize=16, fontweight='bold')
        ax.grid(True, axis='y', linestyle='--', alpha=0.6)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS Read/Write size distribution chart saved to: {save_path}")

        return fig


    def create_vfs_top_processes_chart(self, save_path: str = None):
        if self.vfs_df is None:
            print("VFS data not available, skipping VFS top processes chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        process_ops = self.vfs_df.groupby('comm', observed=True)['op_name'].count().sort_values(ascending=False).head(15)
        
        bars = ax.barh(range(len(process_ops)), process_ops.values, color='mediumpurple', edgecolor='darkslateblue')
        ax.set_xlabel('Number of VFS Operations', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 15 Processes by VFS Operations Count - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_yticks(range(len(process_ops)))
        ax.set_yticklabels(process_ops.index)
        ax.invert_yaxis()  # Highest values at the top
        ax.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                    f'{int(width):,}', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS top processes chart saved to: {save_path}")
            
        return fig

    def create_vfs_process_operation_breakdown_chart(self, save_path: str = None):
        if self.vfs_df is None:
            print("VFS data not available, skipping VFS process operation breakdown chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))
        
        top_processes = self.vfs_df.groupby('comm', observed=True)['op_name'].count().sort_values(ascending=False).head(10).index
        
        top_process_data = self.vfs_df[self.vfs_df['comm'].isin(top_processes)]
        operation_breakdown = top_process_data.groupby(['comm', 'op_name'], observed=True).size().unstack(fill_value=0)
        
        operation_breakdown = operation_breakdown.loc[top_processes]
        
        colors = plt.cm.Set3(np.linspace(0, 1, len(operation_breakdown.columns)))
        operation_breakdown.plot(kind='barh', stacked=True, ax=ax, color=colors, edgecolor='black', linewidth=0.5)
        
        ax.set_xlabel('Number of VFS Operations', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'VFS Operation Types by Top 10 Processes - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        ax.legend(title='VFS Operation Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"VFS process operation breakdown chart saved to: {save_path}")
            
        return fig