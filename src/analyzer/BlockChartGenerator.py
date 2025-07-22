import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional


class BlockChartGenerator:
    
    def __init__(self, workload_name: str, block_df: pd.DataFrame):
        self.workload_name = workload_name
        self.block_df = block_df
        
        if 'lba' not in self.block_df.columns:
            self.block_df['lba'] = self.block_df['sector']

    def create_lba_access_over_time_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping LBA access over time chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(18, 10))
        
        top_processes = self.block_df.groupby('comm', observed=True)['io_size_bytes'].sum().nlargest(5).index.tolist()
        
        plot_df = self.block_df.copy()
        plot_df['process_category'] = plot_df['comm'].apply(lambda x: x if x in top_processes else 'Other')

        colors = sns.color_palette("husl", len(top_processes))
        color_map = {proc: colors[i] for i, proc in enumerate(top_processes)}
        color_map['Other'] = 'lightgray'
        
        sample_size = min(150000, len(plot_df))
        sample_df = plot_df.sample(n=sample_size) if len(plot_df) > sample_size else plot_df

        other_df = sample_df[sample_df['process_category'] == 'Other']
        if not other_df.empty:
            time_numeric = (other_df['datetime'] - sample_df['datetime'].min()).dt.total_seconds()
            lba_values_gb = other_df['lba'] * 512 / (1024**3)
            ax.scatter(time_numeric, lba_values_gb, label='Other', color=color_map['Other'], 
                    alpha=0.4, s=5, edgecolors='none')

        for process_name in top_processes:
            process_df = sample_df[sample_df['process_category'] == process_name]
            if not process_df.empty:
                time_numeric = (process_df['datetime'] - sample_df['datetime'].min()).dt.total_seconds()
                lba_values_gb = process_df['lba'] * 512 / (1024**3)
                ax.scatter(time_numeric, lba_values_gb, label=process_name, color=color_map[process_name],
                        alpha=0.7, s=15, edgecolors='none')

        ax.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax.set_ylabel('LBA Address (GB)', fontsize=12, fontweight='bold')
        ax.set_title(f'LBA Access Over Time by Top 5 Processes - {self.workload_name}', 
                    fontsize=16, fontweight='bold')
        ax.grid(True, alpha=0.4, linestyle='--')
        
        legend = ax.legend(title='Process', bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
        for handle in legend.legend_handles:
            handle.set_sizes([30.0])
        
        plt.tight_layout(rect=[0, 0, 0.9, 1])
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"LBA access over time chart saved to: {save_path}")
            
        return fig

    def create_lba_hotspots_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping LBA hotspots chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))

        lba_access_counts = self.block_df['lba'].value_counts().head(20)
        
        bars = ax.bar(range(len(lba_access_counts)), lba_access_counts.values, color='coral', edgecolor='darkred')
        ax.set_xlabel('LBA Rank (Most to Least Accessed)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Access Count', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 20 Most Accessed LBAs (Hotspots) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_xticks(range(len(lba_access_counts)))
        ax.set_xticklabels([f"LBA {lba}" for lba in lba_access_counts.index], rotation=45, ha="right")
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"LBA hotspots chart saved to: {save_path}")
            
        return fig

    def create_lba_region_distribution_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping LBA region chart.")
            return None

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        min_lba = self.block_df['lba'].min()
        max_lba = self.block_df['lba'].max()
        lba_range = max_lba - min_lba

        if lba_range <= 0:
            print("LBA range is zero, skipping region distribution chart.")
            return None

        num_regions = 20
        region_size = lba_range / num_regions
        self.block_df['lba_region'] = ((self.block_df['lba'] - min_lba) / region_size).astype(int)
        self.block_df['lba_region'] = self.block_df['lba_region'].clip(0, num_regions - 1)
        
        region_access = self.block_df['lba_region'].value_counts().sort_index()
        
        region_labels = [f"{min_lba*512/(1024**3) + i*region_size*512/(1024**3):.1f}G" for i in region_access.index]

        bars = ax.bar(region_labels, region_access.values, color='seagreen', edgecolor='darkgreen')
        ax.set_xlabel('Start of LBA Region (GB)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Access Count', fontsize=12, fontweight='bold')
        ax.set_title(f'Access Distribution Across LBA Regions - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.tick_params(axis='x', rotation=45)
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"LBA region distribution chart saved to: {save_path}")
            
        return fig
    
    def create_access_pattern_chart(self, save_path: str = None):
        if self.block_df is None or len(self.block_df) < 2:
            print("Not enough block data to analyze access patterns.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(10, 8))
            
        sorted_df = self.block_df.sort_values('timestamp')
        lba_diffs = sorted_df['lba'].diff().abs()
        
        sequential_threshold = 64
        sequential_accesses = (lba_diffs <= sequential_threshold).sum()
        random_accesses = (lba_diffs > sequential_threshold).sum()
        
        pattern_values = [sequential_accesses, random_accesses]
        pattern_labels = [f'Sequential (≤{sequential_threshold*512/1024}KB)', 'Random']
        colors = ['skyblue', 'salmon']
        explode = (0.05, 0)
        
        wedges, texts, autotexts = ax.pie(
            pattern_values, 
            labels=pattern_labels, 
            autopct='%1.1f%%', 
            colors=colors, 
            startangle=90,
            explode=explode,
            textprops={'fontweight': 'bold'}
        )
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(14)
            
        ax.set_title(f'Sequential vs. Random Access Pattern - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.axis('equal')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Access pattern chart saved to: {save_path}")
            
        return fig

    def create_io_size_pattern_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping I/O size pattern chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        sample_size = min(50000, len(self.block_df))
        sample_df = self.block_df.sample(n=sample_size) if len(self.block_df) > sample_size else self.block_df
        
        ax.scatter(sample_df['io_size_bytes'] / 1024, range(len(sample_df)), 
                alpha=0.5, s=5, color='purple')
                
        ax.set_xlabel('I/O Size (KB)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Operation Index (Sampled)', fontsize=12, fontweight='bold')
        ax.set_title(f'I/O Size Pattern - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_xscale('log') 
        ax.grid(True, which="both", ls="--", alpha=0.4)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"I/O size pattern chart saved to: {save_path}")
        
        return fig

    def create_performance_stats_image(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping performance stats image.")
            return None

        fig, ax = plt.subplots(1, 1, figsize=(10, 12))
        
        duration = (self.block_df['timestamp'].max() - self.block_df['timestamp'].min()) / 1e9
        
        if duration > 300: # > 5 minutes
            time_window = '10s'
            window_seconds = 10
        else:
            time_window = '1s'
            window_seconds = 1
            
        temporal_data = self.block_df.groupby(pd.Grouper(key='datetime', freq=time_window)).agg(
            operation_count=('operation', 'count'),
            total_bytes=('io_size_bytes', 'sum')
        )
        
        iops_data = temporal_data['operation_count'] / window_seconds
        throughput_data_mbs = temporal_data['total_bytes'] / (window_seconds * 1024**2)
        
        stats_text = f"""
    PERFORMANCE METRICS

    Duration: {duration:.1f} seconds
    Total Operations: {len(self.block_df):,}
    Total Data: {self.block_df['io_size_bytes'].sum() / 1024**3:.2f} GB

    THROUGHPUT METRICS
    Average IOPS: {len(self.block_df) / duration:.1f}
    Peak IOPS (per {time_window}): {iops_data.max():.1f}
    Average Throughput: {self.block_df['io_size_bytes'].sum() / (duration * 1024**2):.1f} MB/s
    Peak Throughput (per {time_window}): {throughput_data_mbs.max():.1f} MB/s

    I/O SIZE METRICS
    Average I/O Size: {self.block_df['io_size_bytes'].mean() / 1024:.1f} KB
    Median I/O Size: {self.block_df['io_size_bytes'].median() / 1024:.1f} KB
    95th Percentile: {self.block_df['io_size_bytes'].quantile(0.95) / 1024:.1f} KB

    WORKLOAD CHARACTERISTICS
    Read Operations: {len(self.block_df[self.block_df['operation'].str.contains('read', case=False, na=False)]):,}
    Write Operations: {len(self.block_df[self.block_df['operation'].str.contains('write', case=False, na=False)]):,}
    Unique Processes: {self.block_df['pid'].nunique()}
        """
        
        ax.text(0.05, 0.98, stats_text.strip(), transform=ax.transAxes, 
                fontsize=12, verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='aliceblue', alpha=0.8))
                
        ax.axis('off')
        ax.set_title(f'Performance Statistics - {self.workload_name}', 
                    fontweight='bold', fontsize=16, pad=20)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Performance statistics image saved to: {save_path}")
        
        return fig

    def create_block_top_processes_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping block top processes chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        process_ops = self.block_df.groupby('comm', observed=True)['operation'].count().sort_values(ascending=False).head(15)
        
        # create horizontal bar chart
        bars = ax.barh(range(len(process_ops)), process_ops.values, color='steelblue', edgecolor='darkblue')
        ax.set_xlabel('Number of Block Operations', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 15 Processes by Block Operations Count - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_yticks(range(len(process_ops)))
        ax.set_yticklabels(process_ops.index)
        ax.invert_yaxis()  # highest values at the top
        ax.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                    f'{int(width):,}', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Block top processes chart saved to: {save_path}")
            
        return fig

    def create_block_process_operation_breakdown_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping block process operation breakdown chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))
        
        # top 10 processes by total operations
        top_processes = self.block_df.groupby('comm', observed=True)['operation'].count().sort_values(ascending=False).head(10).index
        
        # filter data for top processes and create pivot table
        top_process_data = self.block_df[self.block_df['comm'].isin(top_processes)]
        operation_breakdown = top_process_data.groupby(['comm', 'operation'], observed=True).size().unstack(fill_value=0)
        
        # reorder by total operations
        operation_breakdown = operation_breakdown.loc[top_processes]
        
        # create stacked bar chart
        colors = plt.cm.Set1(np.linspace(0, 1, len(operation_breakdown.columns)))
        operation_breakdown.plot(kind='barh', stacked=True, ax=ax, color=colors, edgecolor='black', linewidth=0.5)
        
        ax.set_xlabel('Number of Block Operations', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Block Operation Types by Top 10 Processes - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        ax.legend(title='Block Operation Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Block process operation breakdown chart saved to: {save_path}")
            
        return fig

    def create_block_process_io_volume_breakdown_chart(self, save_path: str = None):
        if self.block_df is None:
            print("Block data not available, skipping block process I/O volume breakdown chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))
        
        # get top 10 processes by total I/O volume
        top_processes = self.block_df.groupby('comm', observed=True)['io_size_bytes'].sum().sort_values(ascending=False).head(10).index
        
        # filter data for top processes and create pivot table 
        top_process_data = self.block_df[self.block_df['comm'].isin(top_processes)]
        volume_breakdown = top_process_data.groupby(['comm', 'operation'], observed=True)['io_size_bytes'].sum().unstack(fill_value=0)
        
        # convert bytes to MB 
        volume_breakdown = volume_breakdown / (1024**2)
        
        # reorder by total I/O volume
        volume_breakdown = volume_breakdown.loc[top_processes]
        
        colors = plt.cm.Set1(np.linspace(0, 1, len(volume_breakdown.columns)))
        volume_breakdown.plot(kind='barh', stacked=True, ax=ax, color=colors, edgecolor='black', linewidth=0.5)
        
        ax.set_xlabel('I/O Volume (MB)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Block I/O Volume by Operation Type - Top 10 Processes - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        ax.legend(title='Block Operation Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Block process I/O volume breakdown chart saved to: {save_path}")
            
        return fig