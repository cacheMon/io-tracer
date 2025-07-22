import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from datetime import datetime
from typing import Optional


class ChartGenerator:
    
    def __init__(self, workload_name: str, block_df: pd.DataFrame = None, vfs_df: pd.DataFrame = None):
        self.workload_name = workload_name
        self.block_df = block_df
        self.vfs_df = vfs_df
    
    def create_operation_types_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(10, 8))
        
        op_counts = self.block_df['operation'].value_counts()
        colors = plt.cm.Set3(np.linspace(0, 1, len(op_counts)))
        wedges, texts, autotexts = ax.pie(op_counts.values, labels=op_counts.index, 
                                         autopct='%1.1f%%', colors=colors, startangle=90)
        ax.set_title(f'Block I/O Operation Types - {self.workload_name}', 
                    fontsize=14, fontweight='bold', pad=20)
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)
        
        total_ops = len(self.block_df)
        ax.text(0.02, 0.98, f'Total Operations: {total_ops:,}', 
               transform=ax.transAxes, fontsize=12, fontweight='bold',
               bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8),
               verticalalignment='top')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Operation types chart saved to: {save_path}")
        
        return fig

    def create_io_size_distribution_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        sample_size = min(50000, len(self.block_df))
        sample_data = self.block_df.sample(n=sample_size) if len(self.block_df) > sample_size else self.block_df
        
        log_sizes = np.log10(sample_data['io_size_bytes'] + 1)
        ax.hist(log_sizes, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        ax.set_xlabel('Log10(I/O Size in Bytes)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
        ax.set_title(f'I/O Size Distribution (Log Scale) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        median_size = self.block_df['io_size_bytes'].median()
        mean_size = self.block_df['io_size_bytes'].mean()
        ax.axvline(x=np.log10(median_size + 1), color='red', linestyle='--', 
                   label=f'Median: {median_size/1024:.1f} KB')
        ax.axvline(x=np.log10(mean_size + 1), color='orange', linestyle='--', 
                   label=f'Mean: {mean_size/1024:.1f} KB')
        ax.legend(fontsize=12)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"I/O size distribution chart saved to: {save_path}")
        
        return fig

    def create_io_size_categories_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        size_bins = [0, 4096, 16384, 65536, 262144, 1048576, float('inf')]
        size_labels = ['≤4KB', '4KB-16KB', '16KB-64KB', '64KB-256KB', '256KB-1MB', '>1MB']
        size_categories = pd.cut(self.block_df['io_size_bytes'], bins=size_bins, labels=size_labels)
        size_counts = size_categories.value_counts()
        
        bars = ax.bar(size_counts.index, size_counts.values, color='lightcoral', edgecolor='darkred')
        ax.set_xlabel('I/O Size Category', fontsize=12, fontweight='bold')
        ax.set_ylabel('Number of Operations', fontsize=12, fontweight='bold')
        ax.set_title(f'I/O Operations by Size Category - {self.workload_name}', 
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
            print(f"I/O size categories chart saved to: {save_path}")
        
        return fig

    def create_temporal_throughput_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(16, 8))
        
        duration = (self.block_df['timestamp'].max() - self.block_df['timestamp'].min()) / 1e9
        if duration > 3600: 
            time_window = '1min'  # 1 minute
        elif duration > 300:  
            time_window = '10s'  # 10 seconds
        else:
            time_window = '1s'   # 1 second
        
        temporal_data = self.block_df.groupby(pd.Grouper(key='datetime', freq=time_window)).agg({
            'io_size_bytes': 'sum',
            'operation': 'count'
        })
        
        window_seconds = pd.Timedelta(time_window).total_seconds()
        temporal_data['throughput_mbs'] = temporal_data['io_size_bytes'] / (1024**2 * window_seconds)
        
        ax.plot(temporal_data.index, temporal_data['throughput_mbs'], 
                color='green', linewidth=2, alpha=0.8)
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Throughput (MB/s)', fontsize=12, fontweight='bold')
        ax.set_title(f'Block I/O Throughput Over Time ({time_window} windows) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        avg_throughput = temporal_data['throughput_mbs'].mean()
        ax.axhline(y=avg_throughput, color='red', linestyle='--', 
                   label=f'Average: {avg_throughput:.1f} MB/s')
        ax.legend(fontsize=12)
        
        for tick in ax.get_xticklabels():
            tick.set_rotation(45)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Temporal throughput chart saved to: {save_path}")
        
        return fig

    def create_temporal_iops_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(16, 8))
        
        duration = (self.block_df['timestamp'].max() - self.block_df['timestamp'].min()) / 1e9
        if duration > 3600:  # > 1 hour
            time_window = '1min'  # 1 minute
        elif duration > 300:  # > 5 minutes
            time_window = '10s'  # 10 seconds
        else:
            time_window = '1s'   # 1 second
        
        temporal_data = self.block_df.groupby(pd.Grouper(key='datetime', freq=time_window)).agg({
            'operation': 'count'
        })
        
        window_seconds = pd.Timedelta(time_window).total_seconds()
        temporal_data['iops'] = temporal_data['operation'] / window_seconds
        
        ax.plot(temporal_data.index, temporal_data['iops'], 
                color='blue', linewidth=2, alpha=0.8)
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('IOPS', fontsize=12, fontweight='bold')
        ax.set_title(f'Block I/O Operations Per Second Over Time ({time_window} windows) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        avg_iops = temporal_data['iops'].mean()
        ax.axhline(y=avg_iops, color='red', linestyle='--', 
                   label=f'Average: {avg_iops:.1f} IOPS')
        ax.legend(fontsize=12)
        
        for tick in ax.get_xticklabels():
            tick.set_rotation(45)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Temporal IOPS chart saved to: {save_path}")
        
        return fig

    def create_process_io_volume_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        process_io = self.block_df.groupby('comm', observed=True)['io_size_bytes'].sum().sort_values(ascending=False).head(15)
        process_io_mb = process_io / 1024**2
        
        bars = ax.barh(range(len(process_io_mb)), process_io_mb.values, color='coral')
        ax.set_xlabel('Total I/O (MB)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 15 Block Processes by I/O Volume - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_yticks(range(len(process_io_mb)))
        ax.set_yticklabels(process_io_mb.index)
        ax.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                    f'{width:.1f}', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Process I/O volume chart saved to: {save_path}")
        
        return fig

    def create_process_operation_count_chart(self, save_path: str = None):
        """Create process operation count chart."""
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        process_ops = self.block_df.groupby('comm', observed=True)['operation'].count().sort_values(ascending=False).head(15)
        
        bars = ax.barh(range(len(process_ops)), process_ops.values, color='lightblue')
        ax.set_xlabel('Number of Operations', fontsize=12, fontweight='bold')
        ax.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 15 Processes by Block Operation Count - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_yticks(range(len(process_ops)))
        ax.set_yticklabels(process_ops.index)
        ax.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                    f'{int(width):,}', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Process operation count chart saved to: {save_path}")
        
        return fig

    def create_read_operations_chart(self, save_path: str = None):
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        read_ops = self.block_df[self.block_df['operation'].str.contains('read', case=False, na=False)]
        write_ops = self.block_df[self.block_df['operation'].str.contains('write', case=False, na=False)]
        
        op_counts = [len(read_ops), len(write_ops)]
        op_labels = ['Read Operations', 'Write Operations']
        colors = ['lightblue', 'lightcoral']
        
        bars = ax.bar(op_labels, op_counts, color=colors, edgecolor='black')
        ax.set_ylabel('Number of Operations', fontsize=12, fontweight='bold')
        ax.set_title(f'Block Read vs Write Operations Count - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        total_ops = sum(op_counts)
        for i, bar in enumerate(bars):
            height = bar.get_height()
            percentage = (height / total_ops) * 100 if total_ops > 0 else 0
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}\n({percentage:.1f}%)', 
                    ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Read operations chart saved to: {save_path}")
        
        return fig

    def create_data_volume_chart(self, save_path: str = None):
        """Create data volume analysis chart."""
        if self.block_df is None:
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        read_ops = self.block_df[self.block_df['operation'].str.contains('read', case=False, na=False)]
        write_ops = self.block_df[self.block_df['operation'].str.contains('write', case=False, na=False)]
        
        read_bytes = read_ops['io_size_bytes'].sum() / 10**6 if len(read_ops) > 0 else 0  # GB
        write_bytes = write_ops['io_size_bytes'].sum() / 10**6 if len(write_ops) > 0 else 0  # GB
        
        volume_data = [read_bytes, write_bytes]
        volume_labels = ['Read Data (MB)', 'Write Data (MB)']
        colors = ['lightblue', 'lightcoral']
        
        bars = ax.bar(volume_labels, volume_data, color=colors, edgecolor='black')
        ax.set_ylabel('Data Volume (MB)', fontsize=12, fontweight='bold')
        ax.set_title(f'Block Read vs Write Data Volume - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        total_volume = sum(volume_data)
        for i, bar in enumerate(bars):
            height = bar.get_height()
            percentage = (height / total_volume) * 100 if total_volume > 0 else 0
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f} MB\n({percentage:.1f}%)', 
                    ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Data volume chart saved to: {save_path}")
        
        return fig

    def create_all_charts(self, output_dir: str = "."):
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        charts_created = []
        
        print(f"Creating individual charts for workload: {self.workload_name}")
        
        chart_functions = {
            "operation_types": self.create_operation_types_chart,
            "io_size_distribution": self.create_io_size_distribution_chart,
            "io_size_categories": self.create_io_size_categories_chart,
            "temporal_throughput": self.create_temporal_throughput_chart,
            "temporal_iops": self.create_temporal_iops_chart,
            "process_io_volume": self.create_process_io_volume_chart,
            "process_operation_count": self.create_process_operation_count_chart,
            "read_operations": self.create_read_operations_chart,
            "data_volume": self.create_data_volume_chart,
        }

        for name, func in chart_functions.items():
            try:
                fig = func()
                if fig:
                    chart_path = output_dir / f"{self.workload_name}_{name}_{timestamp}.png"
                    fig.savefig(chart_path, dpi=300, bbox_inches='tight')
                    plt.close(fig)
                    charts_created.append(str(chart_path))
            except Exception as e:
                print(f"Failed to create {name} chart: {e}")

        print(f"Successfully created {len(charts_created)} charts:")
        for chart in charts_created:
            print(f"  - {Path(chart).name}")
        
        return charts_created