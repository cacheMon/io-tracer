#!/usr/bin/env python3

import argparse
from pathlib import Path
import random

import pandas as pd
from src.utility.utils import logger
from src.analyzer.log_parser import parse_trace_log
from src.analyzer.time_series_analysis import time_series_analysis    
from src.analyzer.heatmap_file_access import heatmap_file_access   
from src.analyzer.latency_analysis import latency_analysis
from src.analyzer.throughput_analysis import throughput_analysis
from src.analyzer.operation_frequency_analysis import operation_frequency_analysis
from src.analyzer.lba_overtime_analysis import lba_overtime_analysis
from src.analyzer.summary import generate_summary_stats


def analyzer():
    parser = argparse.ArgumentParser(description='Analyze trace logs')
    parser.add_argument('log_file', type=str, help='Trace log file to analyze')
    parser.add_argument('-o', '--output', type=str, default='analysis', help='Output directory for analysis results')
    args = parser.parse_args()
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    logger("info",f"Analyzing trace file: {args.log_file}")
    logger("info",f"Output directory: {output_dir}")
    
    df = parse_trace_log(args.log_file)
    
    if df.empty:
        logger("warning","No valid trace data found in the log file for data analysis.")
        logger("info","Exiting analysis...")
        return
    
    logger("info",f"Parsed {len(df)} traces")
    
    charts_dir = output_dir / "charts"
    charts_dir.mkdir(exist_ok=True)
    
    logger("info","Generating time-series analysis...")
    time_series_analysis(df, charts_dir)
    
    logger("info","Generating file access heatmaps...")
    heatmap_file_access(df, charts_dir)
    
    # print("Analyzing latency distribution...")
    # latency_analysis(df, charts_dir)
    
    logger("info","Calculating throughput...")
    throughput_analysis(df, charts_dir)
    
    logger("info","Analyzing operation frequency...")
    operation_frequency_analysis(df, charts_dir)
    
    logger("info", "Analyzing Logical Block Address Overtime...")
    lba_overtime_analysis(df, charts_dir)

    logger("info","Generating summary statistics...")
    generate_summary_stats(df, output_dir)
    
    logger("info","Analysis complete.")
    logger("info",f"Results saved to {output_dir}/")
    logger("info",f"Charts can be found in {charts_dir}/")

if __name__ == "__main__":
    analyzer()