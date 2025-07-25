import json
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class ReportGenerator:
    
    def __init__(self, workload_name: str, raw_file: str, block_df: pd.DataFrame = None, 
             vfs_df: pd.DataFrame = None, cache_df: pd.DataFrame = None):
        self.workload_name = workload_name
        self.raw_file = raw_file
        self.block_df = block_df
        self.vfs_df = vfs_df
        self.cache_df = cache_df
        self.workload_summary = {}

    def extract_workload_characteristics(self) -> Dict:
        characteristics = {
            'workload_name': self.workload_name,
            'total_duration_seconds': 0,
            'block_stats': {},
            'vfs_stats': {},
            'cache_stats': {}, 
            'io_patterns': {},
            'performance_metrics': {}
        }
        
        if self.block_df is not None and len(self.block_df) > 0:
            duration = (self.block_df['timestamp'].max() - self.block_df['timestamp'].min())
            duration = duration.total_seconds()
            characteristics['total_duration_seconds'] = duration
            
            characteristics['block_stats'] = {
                'total_operations': len(self.block_df),
                'total_bytes': self.block_df['io_size_bytes'].sum(),
                'avg_io_size': self.block_df['io_size_bytes'].mean(),
                'median_io_size': self.block_df['io_size_bytes'].median(),
                'operations_per_second': len(self.block_df) / duration if duration > 0 else 0,
                'bytes_per_second': self.block_df['io_size_bytes'].sum() / duration if duration > 0 else 0,
                'read_ratio': len(self.block_df[self.block_df['operation'].str.contains('read', na=False)]) / len(self.block_df),
                'write_ratio': len(self.block_df[self.block_df['operation'].str.contains('WRITE', na=False)]) / len(self.block_df),
                'unique_processes': self.block_df['pid'].nunique()
            }
            
            size_percentiles = self.block_df['io_size_bytes'].quantile([0.5, 0.75, 0.90, 0.95, 0.99])
            characteristics['io_patterns'] = {
                'p50_io_size': size_percentiles[0.5],
                'p75_io_size': size_percentiles[0.75],
                'p90_io_size': size_percentiles[0.90],
                'p95_io_size': size_percentiles[0.95],
                'p99_io_size': size_percentiles[0.99],
            }
        
        if self.vfs_df is not None and len(self.vfs_df) > 0:
            vfs_duration = (self.vfs_df['timestamp'].max() - self.vfs_df['timestamp'].min())
            vfs_duration = vfs_duration.total_seconds()
            
            characteristics['vfs_stats'] = {
                'total_operations': len(self.vfs_df),
                'total_bytes': self.vfs_df['size_val'].sum(),
                'unique_files': self.vfs_df['filename'].nunique(),
                'operations_per_second': len(self.vfs_df) / vfs_duration if vfs_duration > 0 else 0,
                'avg_file_size': self.vfs_df['size_val'].mean(),
                'read_ops': len(self.vfs_df[self.vfs_df['op_name'] == 'READ']),
                'write_ops': len(self.vfs_df[self.vfs_df['op_name'] == 'WRITE']),
                'open_ops': len(self.vfs_df[self.vfs_df['op_name'] == 'OPEN']),
            }
        
        if hasattr(self, 'cache_df') and self.cache_df is not None and len(self.cache_df) > 0:
            cache_duration = (self.cache_df['timestamp'].max() - self.cache_df['timestamp'].min())
            cache_duration = cache_duration.total_seconds()
            total_ops = len(self.cache_df)
            hits = len(self.cache_df[self.cache_df['status'] == 'HIT'])
            misses = len(self.cache_df[self.cache_df['status'] == 'MISS'])
            
            characteristics['cache_stats'] = {
                'total_operations': total_ops,
                'cache_hits': hits,
                'cache_misses': misses,
                'hit_ratio': (hits / total_ops) if total_ops > 0 else 0,
                'miss_ratio': (misses / total_ops) if total_ops > 0 else 0,
                'operations_per_second': total_ops / cache_duration if cache_duration > 0 else 0,
                'unique_indices': self.cache_df['index'].nunique(),
                'unique_processes': self.cache_df['comm'].nunique(),
                'most_active_process': self.cache_df['comm'].value_counts().index[0] if total_ops > 0 else None,
                'most_accessed_index': self.cache_df['index'].value_counts().index[0] if total_ops > 0 else None
            }
        
        self.workload_summary = characteristics
        return characteristics

    def generate_workload_report(self) -> str:
        characteristics = self.extract_workload_characteristics()
        
        report = []
        report.append("=" * 80)
        report.append(f"WORKLOAD ANALYSIS REPORT: {self.workload_name}")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Source File: {self.raw_file}")
        report.append("")
        
        report.append("WORKLOAD OVERVIEW")
        report.append("-" * 40)
        report.append(f"Total Duration: {characteristics['total_duration_seconds']:.1f} seconds")
        
        if 'block_stats' in characteristics and characteristics['block_stats']:
            block_stats = characteristics['block_stats']
            report.append(f"Total Block Operations: {block_stats['total_operations']:,}")
            report.append(f"Total Data Volume: {block_stats['total_bytes'] / 1024**3:.2f} GB")
            report.append(f"Average IOPS: {block_stats['operations_per_second']:.1f}")
            report.append(f"Average Throughput: {block_stats['bytes_per_second'] / 1024**2:.1f} MB/s")
            report.append(f"Unique Processes: {block_stats['unique_processes']}")
            report.append("")
            
            report.append("I/O PATTERNS")
            report.append("-" * 40)
            report.append(f"Read Ratio: {block_stats['read_ratio']:.1%}")
            report.append(f"Write Ratio: {block_stats['write_ratio']:.1%}")
            report.append(f"Average I/O Size: {block_stats['avg_io_size'] / 1024:.1f} KB")
            report.append(f"Median I/O Size: {block_stats['median_io_size'] / 1024:.1f} KB")
            
            if 'io_patterns' in characteristics:
                io_patterns = characteristics['io_patterns']
                report.append("")
                report.append("I/O SIZE PERCENTILES")
                report.append("-" * 40)
                for percentile, value in io_patterns.items():
                    if 'io_size' in percentile:
                        p = percentile.replace('_io_size', '').upper()
                        report.append(f"{p}: {value / 1024:.1f} KB")
            
            report.append("")
        
        if 'vfs_stats' in characteristics and characteristics['vfs_stats']:
            vfs_stats = characteristics['vfs_stats']
            report.append("VFS OPERATIONS")
            report.append("-" * 40)
            report.append(f"Total VFS Operations: {vfs_stats['total_operations']:,}")
            report.append(f"Unique Files Accessed: {vfs_stats['unique_files']:,}")
            report.append(f"VFS Operations/sec: {vfs_stats['operations_per_second']:.1f}")
            report.append(f"Read Operations: {vfs_stats['read_ops']:,}")
            report.append(f"Write Operations: {vfs_stats['write_ops']:,}")
            report.append(f"Open Operations: {vfs_stats['open_ops']:,}")
            report.append("")
        
        if 'cache_stats' in characteristics and characteristics['cache_stats']:
            cache_stats = characteristics['cache_stats']
            report.append("PAGE CACHE OPERATIONS")
            report.append("-" * 40)
            report.append(f"Total Cache Operations: {cache_stats['total_operations']:,}")
            report.append(f"Cache Hits: {cache_stats['cache_hits']:,}")
            report.append(f"Cache Misses: {cache_stats['cache_misses']:,}")
            report.append(f"Cache Hit Ratio: {cache_stats['hit_ratio']:.1%}")
            report.append(f"Cache Operations/sec: {cache_stats['operations_per_second']:.1f}")
            report.append(f"Unique Cache Indices: {cache_stats['unique_indices']:,}")
            report.append(f"Most Active Process: {cache_stats['most_active_process']}")
            report.append("")
        
        report.append("PERFORMANCE CHARACTERISTICS")
        report.append("-" * 40)
        report.append("This workload can be characterized as:")
        
        if 'cache_stats' in characteristics and characteristics['cache_stats']:
            cache_stats = characteristics['cache_stats']
            hit_ratio = cache_stats['hit_ratio']
            
            if hit_ratio > 0.9:
                cache_behavior = "Excellent cache locality"
            elif hit_ratio > 0.7:
                cache_behavior = "Good cache locality"
            elif hit_ratio > 0.5:
                cache_behavior = "Moderate cache locality"
            else:
                cache_behavior = "Poor cache locality"
            
            report.append(f"- {cache_behavior} (Hit ratio: {hit_ratio:.1%})")
            report.append("")
        
        return "\n".join(report)

    def export_workload_analysis(self, output_dir: str = "."):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        characteristics = self.extract_workload_characteristics()
        characteristics_file = output_dir / f"{self.workload_name}_characteristics_{timestamp}.json"
        with open(characteristics_file, 'w') as f:
            json.dump(characteristics, f, indent=2, default=str)
        
        report = self.generate_workload_report()
        report_file = output_dir / f"{self.workload_name}_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"Workload analysis exported to: {output_dir}")
        print(f"Files created:")
        print(f"  - {characteristics_file.name}")
        print(f"  - {report_file.name}")
        
        return characteristics