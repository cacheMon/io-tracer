import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional
import math


plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 18,
    'axes.labelweight': 'bold',
    "axes.titleweight": "bold",
    'axes.titlesize': 22,
    'legend.fontsize': 18
})

class BlockChartGenerator:
    def __init__(self, workload_name: str, block_df: pd.DataFrame):
        self.workload_name = workload_name
        self.block_df = block_df.copy()
        self.block_df = self.block_df[self.block_df['sector'] < 2**64 - 1]
        if 'lba' not in self.block_df.columns:
            self.block_df['lba'] = self.block_df['sector']

    def _create_figure(self, width=8.27, height=5.5):
        return plt.subplots(1, 1, figsize=(width, height))

    def _save_figure(self, fig, save_path: Optional[str]):
        if save_path:
            fig.savefig(save_path, dpi=300, bbox_inches='tight', format='pdf')
            print(f"Saved: {save_path}")

    def create_lba_access_over_time_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return

        top_processes = (
            self.block_df.groupby('comm', observed=True)['io_size_bytes']
            .sum().nlargest(5).index.tolist()
        )

        plot_df = self.block_df[self.block_df['comm'].isin(top_processes)].copy()
        plot_df['process_category'] = plot_df['comm']

        N = 1000
        sample_df = (
            plot_df.groupby('process_category', group_keys=False, observed = False)
            .apply(lambda x: x.sample(n=min(N, len(x)), random_state=42))
            .reset_index(drop=True)
        )

        base_time = sample_df['datetime'].min()
        sample_df['time_secs'] = (sample_df['datetime'] - base_time).dt.total_seconds()

        color_map = {proc: color for proc, color in zip(top_processes, sns.color_palette("colorblind", 5))}

        num_charts = len(top_processes)
        cols = 2
        rows = math.ceil(num_charts / cols)

        fig, axes = plt.subplots(rows, cols, figsize=(cols * 6, rows * 4), squeeze=False)
        axes = axes.flatten()

        for i, proc in enumerate(top_processes):
            ax = axes[i]
            sub = sample_df[sample_df['process_category'] == proc]

            hb = ax.hexbin(
                sub['time_secs'], sub['lba'],
                gridsize=150, cmap='viridis', bins='log'
            )

            ax.set_title(f"{proc}")
            ax.set_xlabel("Time (seconds)")
            ax.set_ylabel("LBA Address")
            ax.grid(True, linestyle='--', alpha=0.3)

        for j in range(i + 1, len(axes)):
            axes[j].axis('off')

        fig.suptitle(f"LBA Access Over Time per Process - {self.workload_name}")
        plt.tight_layout(rect=[0, 0, 1, 0.96])

        self._save_figure(fig, save_path)
        return fig


    def create_lba_hotspots_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure()

        top_lbas = self.block_df['lba'].value_counts().head(10)
        ax.bar(range(len(top_lbas)), top_lbas.values, color='coral', edgecolor='darkred')
        ax.set_xticks(range(len(top_lbas)))
        ax.set_xticklabels([f"LBA {lba}" for lba in top_lbas.index], rotation=30, ha='right')
        ax.set_xlabel("LBA (Ranked)")
        ax.set_ylabel("Access Count")
        ax.set_title(f"Top 10 Most Accessed LBAs - {self.workload_name}")
        ax.grid(True, alpha=0.3, axis='y')
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_lba_region_distribution_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure()

        min_lba, max_lba = self.block_df['lba'].min(), self.block_df['lba'].max()

        if max_lba - min_lba == 0:
            return
        num_regions = 5

        # Use pd.cut to create bins
        bins = np.linspace(min_lba, max_lba, num_regions + 1)
        self.block_df['region_bin'] = pd.cut(self.block_df['lba'], bins=bins, right=False)

        region_counts = self.block_df['region_bin'].value_counts().sort_index()
        labels = [f"{int(interval.left)}" for interval in region_counts.index]

        ax.bar(labels, region_counts.values, color='seagreen', edgecolor='darkgreen')
        ax.set_xlabel("Start of LBA Region")
        ax.set_ylabel("Access Count")
        ax.set_title(f"LBA Region Access Distribution - {self.workload_name}")
        ax.tick_params(axis='x', rotation=30)
        ax.grid(True, axis='y', alpha=0.3)
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig


    def create_access_pattern_chart(self, save_path: Optional[str] = None):
        if self.block_df is None or len(self.block_df) < 2:
            return
        fig, ax = self._create_figure(width=6, height=6)

        sorted_df = self.block_df.sort_values('timestamp')
        diffs = sorted_df['lba'].diff().abs()
        threshold = 64
        counts = [sum(diffs <= threshold), sum(diffs > threshold)]
        labels = [f"Sequential (≤{threshold*512//1024}KB)", "Random"]
        ax.pie(counts, labels=labels, autopct='%1.1f%%', colors=['skyblue', 'salmon'],
               startangle=90, explode=(0.05, 0), textprops={'fontweight': 'bold'})
        ax.set_title(f"Access Pattern - {self.workload_name}")
        ax.axis('equal')
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_io_size_pattern_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure()

        sample = self.block_df.sample(n=min(50000, len(self.block_df)))
        ax.scatter(sample['io_size_bytes'] / 1024, range(len(sample)), alpha=0.5, s=5, color='purple')
        ax.set_xlabel("I/O Size (KB)")
        ax.set_ylabel("Operation Index (Sampled)")
        ax.set_xscale('log')
        ax.set_title(f"I/O Size Pattern - {self.workload_name}")
        ax.grid(True, which="both", linestyle="--", alpha=0.3)
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_performance_stats_image(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure(height=6)

        duration = (self.block_df['timestamp'].max() - self.block_df['timestamp'].min())
        duration = duration.total_seconds()
        freq = '10s' if duration > 300 else '1s'
        interval = 10 if duration > 300 else 1

        time_group = self.block_df.groupby(pd.Grouper(key='datetime', freq=freq)).agg(
            ops=('operation', 'count'), bytes=('io_size_bytes', 'sum')
        )
        iops = time_group['ops'] / interval
        mbps = time_group['bytes'] / (interval * 2**20)

        stat_text = f"""
PERFORMANCE METRICS

Duration: {duration:.1f} s
Total Ops: {len(self.block_df):,}
Total Data: {self.block_df['io_size_bytes'].sum() / 2**30:.2f} GB

Average IOPS: {len(self.block_df) / duration:.1f}
Peak IOPS: {iops.max():.1f}
Average Throughput: {self.block_df['io_size_bytes'].sum() / (duration * 2**20):.1f} MB/s
Peak Throughput: {mbps.max():.1f} MB/s

Average I/O Size: {self.block_df['io_size_bytes'].mean() / 1024:.1f} KB
Median I/O Size: {self.block_df['io_size_bytes'].median() / 1024:.1f} KB
95th Percentile: {self.block_df['io_size_bytes'].quantile(0.95) / 1024:.1f} KB

Reads: {len(self.block_df[self.block_df['operation'].str.contains("read", case=False)]):,}
Writes: {len(self.block_df[self.block_df['operation'].str.contains("write", case=False)]):,}
Processes: {self.block_df['pid'].nunique()}
"""
        ax.text(0.01, 0.99, stat_text.strip(), transform=ax.transAxes,
                va='top', family='monospace',
                bbox=dict(facecolor='aliceblue', boxstyle='round', alpha=0.9))
        ax.axis('off')
        ax.set_title(f"Performance Summary - {self.workload_name}", pad=20)
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_block_top_processes_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure()

        top_processes = self.block_df['comm'].value_counts().head(15)
        bars = ax.barh(range(len(top_processes)), top_processes.values,
                       color='steelblue', edgecolor='darkblue')

        ax.set_xlabel("Number of Block Operations")
        ax.set_ylabel("Process")
        ax.set_title(f"Top 15 Processes by Block Ops - {self.workload_name}")
        ax.set_yticks(range(len(top_processes)))
        ax.set_yticklabels(top_processes.index)
        ax.invert_yaxis()
        ax.grid(True, axis='x', alpha=0.3)

        for bar in bars:
            width = bar.get_width()
            ax.text(width + width * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{int(width):,}", va='center', ha='left', fontweight='bold')

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_block_process_operation_breakdown_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure(width=8.5, height=6.5)

        top_comm = self.block_df['comm'].value_counts().head(10).index
        top_df = self.block_df[self.block_df['comm'].isin(top_comm)]
        op_breakdown = top_df.groupby(['comm', 'operation'], observed=True).size().unstack(fill_value=0)
        op_breakdown = op_breakdown.loc[top_comm]

        colors = sns.color_palette("Set2", len(op_breakdown.columns))
        op_breakdown.plot(kind='barh', stacked=True, ax=ax, color=colors, edgecolor='black', linewidth=0.5)

        ax.set_xlabel("Number of Block Operations")
        ax.set_ylabel("Process")
        ax.set_title(f"Operation Breakdown - Top 10 Processes - {self.workload_name}")
        ax.grid(True, axis='x', alpha=0.3)
        ax.legend(title="Operation Type", bbox_to_anchor=(1.05, 1), loc="upper left")
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_block_process_io_volume_breakdown_chart(self, save_path: Optional[str] = None):
        if self.block_df is None:
            return
        fig, ax = self._create_figure(width=8.5, height=6.5)

        top_comm = self.block_df.groupby('comm', observed = True)['io_size_bytes'].sum().nlargest(10).index
        top_df = self.block_df[self.block_df['comm'].isin(top_comm)]
        io_volume = top_df.groupby(['comm', 'operation'], observed=True)['io_size_bytes'].sum().unstack(fill_value=0)
        io_volume = io_volume.loc[top_comm] / (1024**2)  # Convert to MB

        colors = sns.color_palette("Set3", len(io_volume.columns))
        io_volume.plot(kind='barh', stacked=True, ax=ax, color=colors, edgecolor='black', linewidth=0.5)

        ax.set_xlabel("I/O Volume (MB)")
        ax.set_ylabel("Process")
        ax.set_title(f"I/O Volume by Operation Type - Top 10 Processes - {self.workload_name}")
        ax.grid(True, axis='x', alpha=0.3)
        ax.legend(title="Operation Type", bbox_to_anchor=(1.05, 1), loc="upper left")
        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig
