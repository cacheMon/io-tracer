import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional


class CacheChartGenerator:
    
    def __init__(self, workload_name: str, cache_df: pd.DataFrame):
        self.workload_name = workload_name
        self.cache_df = cache_df

    def create_cache_hit_ratio_chart(self, save_path: str = None):
        """Create overall cache hit/miss ratio pie chart"""
        if self.cache_df is None or len(self.cache_df) == 0:
            print("Cache data not available, skipping cache hit ratio chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(10, 8))
        
        hit_counts = self.cache_df['status'].value_counts()
        colors = ['lightgreen' if status == 'HIT' else 'lightcoral' for status in hit_counts.index]
        
        total = len(self.cache_df)
        hit_rate = (hit_counts.get('HIT', 0) / total) * 100 if total > 0 else 0
        miss_rate = (hit_counts.get('MISS', 0) / total) * 100 if total > 0 else 0
        
        wedges, texts, autotexts = ax.pie(
            hit_counts.values, 
            labels=[f'{status}\n({count:,} ops)' for status, count in hit_counts.items()],
            autopct='%1.1f%%', 
            colors=colors, 
            startangle=90,
            explode=(0.05, 0) if len(hit_counts) == 2 else None
        )
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(12)
        
        ax.set_title(f'Page Cache Hit/Miss Ratio - {self.workload_name}', 
                    fontsize=16, fontweight='bold', pad=20)
        
        summary_text = f'Total Cache Operations: {total:,}\nHit Rate: {hit_rate:.1f}%'
        ax.text(0.02, 0.98, summary_text, 
               transform=ax.transAxes, fontsize=12, fontweight='bold',
               bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8),
               verticalalignment='top')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Cache hit ratio chart saved to: {save_path}")
        
        return fig

    def create_cache_hit_ratio_over_time_chart(self, save_path: str = None):
        if self.cache_df is None or len(self.cache_df) == 0:
            print("Cache data not available, skipping cache hit ratio over time chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(16, 8))
        
        duration = (self.cache_df['timestamp'].max() - self.cache_df['timestamp'].min()) / 1e9
        if duration > 3600:  # > 1 hour
            time_window = '1min'
        elif duration > 300:  # > 5 minutes
            time_window = '10s'
        else:
            time_window = '1s'
        
        time_grouped = self.cache_df.groupby([
            pd.Grouper(key='datetime', freq=time_window),
            'status'
        ], observed = False).size().unstack(fill_value=0)
        
        if 'HIT' not in time_grouped.columns:
            time_grouped['HIT'] = 0
        if 'MISS' not in time_grouped.columns:
            time_grouped['MISS'] = 0
            
        time_grouped['total'] = time_grouped['HIT'] + time_grouped['MISS']
        time_grouped['hit_ratio'] = (time_grouped['HIT'] / time_grouped['total'] * 100).fillna(0)
        
        ax.plot(time_grouped.index, time_grouped['hit_ratio'], 
                color='green', linewidth=2, alpha=0.8, marker='o', markersize=4)
        
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Cache Hit Ratio (%)', fontsize=12, fontweight='bold')
        ax.set_title(f'Page Cache Hit Ratio Over Time ({time_window} windows) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 100)
        
        avg_hit_ratio = time_grouped['hit_ratio'].mean()
        ax.axhline(y=avg_hit_ratio, color='red', linestyle='--', 
                   label=f'Average: {avg_hit_ratio:.1f}%')
        ax.legend(fontsize=12)
        
        for tick in ax.get_xticklabels():
            tick.set_rotation(45)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Cache hit ratio over time chart saved to: {save_path}")
        
        return fig

    def create_cache_operations_by_process_chart(self, save_path: str = None):
        if self.cache_df is None or len(self.cache_df) == 0:
            print("Cache data not available, skipping cache operations by process chart.")
            return None
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 8))
        
        process_ops = self.cache_df.groupby('comm', observed=True).size().sort_values(ascending=False).head(15)
        
        bars1 = ax1.barh(range(len(process_ops)), process_ops.values, color='skyblue', edgecolor='darkblue')
        ax1.set_xlabel('Number of Cache Operations', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax1.set_title(f'Top 15 Processes by Cache Operations - {self.workload_name}', 
                     fontsize=14, fontweight='bold')
        ax1.set_yticks(range(len(process_ops)))
        ax1.set_yticklabels(process_ops.index)
        ax1.invert_yaxis()
        ax1.grid(True, alpha=0.3, axis='x')
        
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                    f'{int(width):,}', ha='left', va='center', fontweight='bold')
        
        top_processes = process_ops.head(10).index
        process_hit_ratios = []
        
        for process in top_processes:
            process_data = self.cache_df[self.cache_df['comm'] == process]
            hits = len(process_data[process_data['status'] == 'HIT'])
            total = len(process_data)
            hit_ratio = (hits / total * 100) if total > 0 else 0
            process_hit_ratios.append(hit_ratio)
        
        bars2 = ax2.barh(range(len(top_processes)), process_hit_ratios, color='lightgreen', edgecolor='darkgreen')
        ax2.set_xlabel('Cache Hit Ratio (%)', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Process', fontsize=12, fontweight='bold')
        ax2.set_title(f'Cache Hit Ratios by Top 10 Processes - {self.workload_name}', 
                     fontsize=14, fontweight='bold')
        ax2.set_yticks(range(len(top_processes)))
        ax2.set_yticklabels(top_processes)
        ax2.invert_yaxis()
        ax2.grid(True, alpha=0.3, axis='x')
        ax2.set_xlim(0, 100)
        
        for i, bar in enumerate(bars2):
            width = bar.get_width()
            ax2.text(width + 1, bar.get_y() + bar.get_height()/2.,
                    f'{width:.1f}%', ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Cache operations by process chart saved to: {save_path}")
        
        return fig

    def create_cache_hotspots_chart(self, save_path: str = None):
        if self.cache_df is None or len(self.cache_df) == 0:
            print("Cache data not available, skipping cache hotspots chart.")
            return None
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        index_access = self.cache_df['index'].value_counts().head(20)
        
        bars = ax.bar(range(len(index_access)), index_access.values, color='orange', edgecolor='darkorange')
        ax.set_xlabel('Cache Index Rank (Most to Least Accessed)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Access Count', fontsize=12, fontweight='bold')
        ax.set_title(f'Top 20 Most Accessed Cache Indices (Hotspots) - {self.workload_name}', 
                    fontsize=14, fontweight='bold')
        ax.set_xticks(range(len(index_access)))
        ax.set_xticklabels([f"Idx {idx}" for idx in index_access.index], rotation=45, ha="right")
        ax.grid(True, alpha=0.3, axis='y')
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Cache hotspots chart saved to: {save_path}")
        
        return fig

    def create_cache_performance_stats_image(self, save_path: str = None):
        if self.cache_df is None or len(self.cache_df) == 0:
            print("Cache data not available, skipping cache performance stats.")
            return None

        fig, ax = plt.subplots(1, 1, figsize=(10, 12))
        
        total_ops = len(self.cache_df)
        hits = len(self.cache_df[self.cache_df['status'] == 'HIT'])
        misses = len(self.cache_df[self.cache_df['status'] == 'MISS'])
        hit_ratio = (hits / total_ops * 100) if total_ops > 0 else 0
        miss_ratio = (misses / total_ops * 100) if total_ops > 0 else 0
        
        duration = (self.cache_df['timestamp'].max() - self.cache_df['timestamp'].min()) / 1e9
        ops_per_second = total_ops / duration if duration > 0 else 0
        
        unique_indices = self.cache_df['index'].nunique()
        unique_processes = self.cache_df['comm'].nunique()
        
        top_process = self.cache_df['comm'].value_counts().index[0] if len(self.cache_df) > 0 else "N/A"
        top_process_ops = self.cache_df['comm'].value_counts().iloc[0] if len(self.cache_df) > 0 else 0
        
        top_index = self.cache_df['index'].value_counts().index[0] if len(self.cache_df) > 0 else "N/A"
        top_index_accesses = self.cache_df['index'].value_counts().iloc[0] if len(self.cache_df) > 0 else 0
        
        stats_text = f"""
    PAGE CACHE PERFORMANCE METRICS

    Duration: {duration:.1f} seconds
    Total Cache Operations: {total_ops:,}
    
    HIT/MISS STATISTICS
    Cache Hits: {hits:,} ({hit_ratio:.1f}%)
    Cache Misses: {misses:,} ({miss_ratio:.1f}%)
    
    OPERATION RATE
    Average Operations/sec: {ops_per_second:.1f}
    
    ACCESS PATTERNS
    Unique Cache Indices: {unique_indices:,}
    Unique Processes: {unique_processes:,}
    
    TOP ACTIVITY
    Most Active Process: {top_process} ({top_process_ops:,} ops)
    Most Accessed Index: {top_index} ({top_index_accesses:,} accesses)
    
    CACHE EFFICIENCY
    Hit Ratio: {hit_ratio:.1f}% {'(Excellent)' if hit_ratio > 90 else '(Good)' if hit_ratio > 70 else '(Poor)' if hit_ratio < 50 else '(Fair)'}
        """
        
        ax.text(0.05, 0.98, stats_text.strip(), transform=ax.transAxes, 
                fontsize=12, verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightcyan', alpha=0.8))
                
        ax.axis('off')
        ax.set_title(f'Page Cache Performance Statistics - {self.workload_name}', 
                    fontweight='bold', fontsize=16, pad=20)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Cache performance statistics image saved to: {save_path}")
        
        return fig