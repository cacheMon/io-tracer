import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from .DataParser import DataParser
from .ChartGenerator import ChartGenerator
from .BlockChartGenerator import BlockChartGenerator
from .VFSChartGenerator import VFSChartGenerator
from .ReportGenerator import ReportGenerator


class IOTraceAnalyzer:
    def __init__(self, raw_file: str, workload_name: str = None):
        self.raw_file = raw_file
        self.workload_name = workload_name or Path(raw_file).stem
        self.block_df = None
        self.vfs_df = None
        
        self.data_parser = DataParser(raw_file)
        self.chart_generator = None
        self.block_chart_generator = None
        self.vfs_chart_generator = None
        self.report_generator = None
        
        print(f"Initializing analysis for workload: {self.workload_name}")
        self._prepare_dataframes()

    def _prepare_dataframes(self):
        self.block_df, self.vfs_df = self.data_parser.parse()
        
        self.chart_generator = ChartGenerator(self.workload_name, self.block_df, self.vfs_df)
        
        if self.block_df is not None:
            self.block_chart_generator = BlockChartGenerator(self.workload_name, self.block_df)
        
        if self.vfs_df is not None:
            self.vfs_chart_generator = VFSChartGenerator(self.workload_name, self.vfs_df)
        
        self.report_generator = ReportGenerator(self.workload_name, self.raw_file, self.block_df, self.vfs_df)

    def extract_workload_characteristics(self) -> Dict:
        if self.report_generator:
            return self.report_generator.extract_workload_characteristics()
        return {}

    def generate_workload_report(self) -> str:
        if self.report_generator:
            return self.report_generator.generate_workload_report()
        return ""

    def create_operation_types_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_operation_types_chart(save_path)
        return None

    def create_io_size_distribution_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_io_size_distribution_chart(save_path)
        return None

    def create_io_size_categories_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_io_size_categories_chart(save_path)
        return None

    def create_temporal_throughput_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_temporal_throughput_chart(save_path)
        return None

    def create_temporal_iops_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_temporal_iops_chart(save_path)
        return None

    def create_process_io_volume_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_process_io_volume_chart(save_path)
        return None

    def create_process_operation_count_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_process_operation_count_chart(save_path)
        return None

    def create_read_operations_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_read_operations_chart(save_path)
        return None

    def create_data_volume_chart(self, save_path: str = None):
        if self.chart_generator:
            return self.chart_generator.create_data_volume_chart(save_path)
        return None

    def create_lba_access_over_time_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_lba_access_over_time_chart(save_path)
        return None

    def create_lba_hotspots_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_lba_hotspots_chart(save_path)
        return None

    def create_lba_region_distribution_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_lba_region_distribution_chart(save_path)
        return None

    def create_access_pattern_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_access_pattern_chart(save_path)
        return None

    def create_io_size_pattern_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_io_size_pattern_chart(save_path)
        return None

    def create_performance_stats_image(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_performance_stats_image(save_path)
        return None

    def create_vfs_operation_types_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_operation_types_chart(save_path)
        return None

    def create_file_access_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_file_access_chart(save_path)
        return None

    def create_vfs_open_flags_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_open_flags_chart(save_path)
        return None

    def create_vfs_iops_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_iops_chart(save_path)
        return None

    def create_vfs_rw_size_distribution_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_rw_size_distribution_chart(save_path)
        return None

    def create_vfs_top_processes_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_top_processes_chart(save_path)
        return None

    def create_vfs_process_operation_breakdown_chart(self, save_path: str = None):
        if self.vfs_chart_generator:
            return self.vfs_chart_generator.create_vfs_process_operation_breakdown_chart(save_path)
        return None

    def create_block_top_processes_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_block_top_processes_chart(save_path)
        return None

    def create_block_process_operation_breakdown_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_block_process_operation_breakdown_chart(save_path)
        return None

    def create_block_process_io_volume_breakdown_chart(self, save_path: str = None):
        if self.block_chart_generator:
            return self.block_chart_generator.create_block_process_io_volume_breakdown_chart(save_path)
        return None

    def create_all_charts(self, output_dir: str = "."):
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        charts_created = []
        
        print(f"Creating individual charts for workload: {self.workload_name}")
        
        # Basic charts from ChartGenerator
        basic_chart_functions = {
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
        
        # Block-specific charts from BlockChartGenerator
        block_chart_functions = {
            "lba_access_over_time": self.create_lba_access_over_time_chart,
            "lba_hotspots": self.create_lba_hotspots_chart,
            "lba_region_distribution": self.create_lba_region_distribution_chart,
            "access_pattern": self.create_access_pattern_chart,
            "io_size_pattern": self.create_io_size_pattern_chart,
            "performance_stats": self.create_performance_stats_image,
            "block_top_processes": self.create_block_top_processes_chart, 
            "block_process_breakdown": self.create_block_process_operation_breakdown_chart,  
            "block_process_io_volume": self.create_block_process_io_volume_breakdown_chart,
        }
        
        # VFS-specific charts from VFSChartGenerator
        vfs_chart_functions = {
            "vfs_operations": self.create_vfs_operation_types_chart,
            "file_access": self.create_file_access_chart,
            "vfs_open_flags": self.create_vfs_open_flags_chart,
            "vfs_iops": self.create_vfs_iops_chart,
            "vfs_rw_size_distribution": self.create_vfs_rw_size_distribution_chart,
            "vfs_top_processes": self.create_vfs_top_processes_chart,  
            "vfs_process_breakdown": self.create_vfs_process_operation_breakdown_chart,  
        }
        
        all_chart_functions = {**basic_chart_functions, **block_chart_functions}
        
        if self.vfs_df is not None:
            all_chart_functions.update(vfs_chart_functions)

        for name, func in all_chart_functions.items():
            try:
                fig = func()
                if fig:
                    chart_path = output_dir / f"{self.workload_name}_{name}_{timestamp}.png"
                    fig.savefig(chart_path, dpi=300, bbox_inches='tight')
                    import matplotlib.pyplot as plt
                    plt.close(fig)
                    charts_created.append(str(chart_path))
            except Exception as e:
                print(f"Failed to create {name} chart: {e}")

        print(f"Successfully created {len(charts_created)} charts:")
        for chart in charts_created:
            print(f"  - {Path(chart).name}")
        
        return charts_created

    def export_workload_analysis(self, output_dir: str = "."):
        characteristics = None
        if self.report_generator:
            characteristics = self.report_generator.export_workload_analysis(output_dir)
        
        charts_created = self.create_all_charts(output_dir)
        
        return characteristics