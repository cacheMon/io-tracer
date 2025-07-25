import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 18,
    'axes.labelweight': 'bold',
    "axes.titlesize": 32,
    "axes.labelsize": 18,
    "legend.fontsize": 18
})

class CacheChartGenerator:
    
    def __init__(self, workload_name: str, cache_df: pd.DataFrame):
        self.workload_name = workload_name
        self.cache_df = cache_df
        sns.set(style="whitegrid")

    def _create_figure(self, width: float = 10, height: float = 8):
        fig, ax = plt.subplots(figsize=(width, height))
        return fig, ax

    def _save_figure(self, fig, save_path: Optional[str]):
        if save_path:
            fig.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')

    def create_cache_hit_ratio_chart(self, save_path: str = None):
        if self.cache_df is None or self.cache_df.empty:
            return None

        fig, ax = self._create_figure()

        hit_counts = self.cache_df['status'].value_counts()
        total_ops = hit_counts.sum()
        colors = ['#66c2a5' if status == 'HIT' else '#fc8d62' for status in hit_counts.index]

        wedges, texts, autotexts = ax.pie(
            hit_counts.values,
            labels=[f"{status} ({count:,})" for status, count in hit_counts.items()],
            autopct='%1.1f%%',
            colors=colors,
            startangle=90,
            explode=(0.05, 0) if len(hit_counts) == 2 else None
        )

        for t in autotexts:
            t.set_color('white')
            t.set_fontweight('bold')

        ax.set_title(f"Page Cache Hit/Miss Ratio – {self.workload_name}", fontweight='bold')

        summary = f"Total Cache Operations: {total_ops:,}\nHit Rate: {hit_counts.get('HIT', 0)/total_ops:.1%}"
        ax.text(0.02, 0.98, summary,
                transform=ax.transAxes,
                fontweight='bold',
                verticalalignment='top',
                bbox=dict(boxstyle="round", facecolor='whitesmoke', edgecolor='gray'))

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_cache_hit_ratio_over_time_chart(self, save_path: str = None):
        if self.cache_df is None or self.cache_df.empty:
            return None

        fig, ax = self._create_figure(width=14, height=6)

        duration = (self.cache_df['timestamp'].max() - self.cache_df['timestamp'].min())
        duration = duration.total_seconds()
        if duration > 3600:
            freq = '1min'
        elif duration > 300:
            freq = '10s'
        else:
            freq = '1s'

        grouped = self.cache_df.groupby([pd.Grouper(key='timestamp', freq=freq), 'status'], observed = False).size().unstack(fill_value=0)
        grouped['hit_ratio'] = (grouped.get('HIT', 0) / grouped.sum(axis=1)).fillna(0) * 100

        ax.plot(grouped.index, grouped['hit_ratio'], label="Hit Ratio", color='seagreen', marker='o', linewidth=2)
        ax.axhline(grouped['hit_ratio'].mean(), color='red', linestyle='--',
                   label=f"Avg: {grouped['hit_ratio'].mean():.1f}%")

        ax.set_xlabel("Time")
        ax.set_ylabel("Cache Hit Ratio (%)")
        ax.set_title(f"Cache Hit Ratio Over Time ({freq} Window) – {self.workload_name}", fontweight='bold')
        ax.set_ylim(0, 100)
        ax.grid(True, alpha=0.3)
        ax.legend()
        for label in ax.get_xticklabels():
            label.set_rotation(45)

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_cache_operations_by_process_chart(self, save_path: str = None):
        if self.cache_df is None or self.cache_df.empty:
            return None

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12))

        top_processes = self.cache_df['comm'].value_counts().head(15)
        ax1.barh(top_processes.index[::-1], top_processes.values[::-1], color='skyblue', edgecolor='black')
        ax1.set_title(f"Top 15 Processes by Cache Ops – {self.workload_name}", fontweight='bold')
        ax1.set_xlabel("Cache Operations")
        ax1.grid(True, axis='x', alpha=0.3)

        hit_ratios = []
        for comm in top_processes.index[:10]:
            sub_df = self.cache_df[self.cache_df['comm'] == comm]
            ratio = sub_df['status'].value_counts(normalize=True).get('HIT', 0) * 100
            hit_ratios.append(ratio)

        ax2.barh(top_processes.index[:10][::-1], hit_ratios[::-1], color='lightgreen', edgecolor='black')
        ax2.set_title(f"Cache Hit Ratio (Top 10 Processes) – {self.workload_name}", fontweight='bold')
        ax2.set_xlabel("Hit Ratio (%)")
        ax2.set_xlim(0, 100)
        ax2.grid(True, axis='x', alpha=0.3)

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_cache_hotspots_chart(self, save_path: str = None):
        if self.cache_df is None or self.cache_df.empty:
            return None

        fig, ax = self._create_figure(width=12, height=6)

        top_indices = self.cache_df['index'].value_counts().head(20)
        ax.bar(range(len(top_indices)), top_indices.values, color='darkorange', edgecolor='black')
        ax.set_xticks(range(len(top_indices)))
        ax.set_xticklabels([f"Idx {idx}" for idx in top_indices.index], rotation=45, ha='right')
        ax.set_title(f"Cache Hotspots – Top 20 Indices – {self.workload_name}", fontweight='bold')
        ax.set_xlabel("Cache Index")
        ax.set_ylabel("Access Count")
        ax.grid(True, axis='y', alpha=0.3)

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig

    def create_cache_performance_stats_image(self, save_path: str = None):
        if self.cache_df is None or self.cache_df.empty:
            return None

        fig, ax = self._create_figure(width=9, height=11)

        total = len(self.cache_df)
        hits = self.cache_df['status'].value_counts().get('HIT', 0)
        misses = self.cache_df['status'].value_counts().get('MISS', 0)
        hit_ratio = hits / total * 100 if total > 0 else 0

        duration = (self.cache_df['timestamp'].max() - self.cache_df['timestamp'].min())
        duration = duration.total_seconds()
        ops_per_sec = total / duration if duration > 0 else 0

        text = f"""
PAGE CACHE PERFORMANCE SUMMARY

Duration: {duration:.1f} s
Total Operations: {total:,}
Average Ops/sec: {ops_per_sec:.1f}

Cache Hits: {hits:,} ({hit_ratio:.1f}%)
Cache Misses: {misses:,} ({100 - hit_ratio:.1f}%)

Unique Processes: {self.cache_df['comm'].nunique()}
Unique Cache Indices: {self.cache_df['index'].nunique()}

Most Active Process: {self.cache_df['comm'].mode().values[0]} 
Most Accessed Index: {self.cache_df['index'].mode().values[0]}
"""

        ax.text(0.05, 0.95, text.strip(), transform=ax.transAxes,
                va='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='azure', edgecolor='lightblue'))
        ax.set_title(f"Cache Performance Statistics – {self.workload_name}", fontweight='bold')
        ax.axis('off')

        plt.tight_layout()
        self._save_figure(fig, save_path)
        return fig
