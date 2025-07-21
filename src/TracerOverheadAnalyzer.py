import os
import signal
import time
import subprocess
import json
from pathlib import Path
from datetime import datetime
import statistics
from OverheadMeasurement import OverheadMeasurement
from BenchmarkSuite import BenchmarkSuite
from utility.utils import logger


class TracerOverheadAnalyzer:
    """Main class to orchestrate overhead measurement"""
    
    def __init__(self, tracer_command, output_dir="overhead_analysis"):
        self.tracer_command = tracer_command
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.monitor = OverheadMeasurement(str(self.output_dir / "system_metrics"))
        self.benchmark = BenchmarkSuite(str(self.output_dir / "benchmarks"))
        
    def run_baseline_measurement(self, duration=60):
        """Run measurements without tracer (baseline)"""
        print("Running baseline measurements (no tracer)...")
        
        baseline_results = {}
        
        # System monitoring
        self.monitor.start_system_monitoring()
        time.sleep(2)  # Stabilize
        
        # CPU benchmark
        print("  Running CPU benchmark...")
        baseline_results['cpu_benchmark'] = self.benchmark.run_cpu_intensive_benchmark(30)
        
        # I/O benchmark  
        print("  Running I/O benchmark...")
        baseline_results['io_benchmark'] = self.benchmark.run_io_intensive_benchmark(30)
        
        # Let system monitoring run a bit longer
        # time.sleep(duration - 60)
        
        self.monitor.stop_system_monitoring()
        
        baseline_results['system_metrics'] = {
            'cpu_usage': self.monitor.measurements['cpu_usage'].copy(),
            'memory_usage': self.monitor.measurements['memory_usage'].copy(),
            'disk_io': self.monitor.measurements['disk_io'].copy()
        }
        
        # Clear measurements for next run
        self.monitor.measurements = {k: [] for k in self.monitor.measurements}
        
        return baseline_results
    
    def run_with_tracer_measurement(self, duration=60):
        """Run measurements with tracer active"""
        print("Running measurements with tracer active...")
        
        tracer_results = {}
        
        # Start system monitoring
        self.monitor.start_system_monitoring()
        time.sleep(1)
        
        # Start tracer
        print(f"  Starting tracer: {self.tracer_command}")
        tracer_process = subprocess.Popen(
            self.tracer_command, 
            shell=True, 
            preexec_fn=os.setsid, 
            # stdout=subprocess.DEVNULL
            )
        
        # Monitor tracer process
        tracer_pid = tracer_process.pid
        time.sleep(2)  # Let tracer initialize
        
        # Run benchmarks while tracer is active
        print("  Running CPU benchmark with tracer...")
        tracer_results['cpu_benchmark'] = self.benchmark.run_cpu_intensive_benchmark(30)
        
        # Monitor tracer during I/O benchmark
        print("  Running I/O benchmark with tracer...")
        tracer_results['io_benchmark'] = self.benchmark.run_io_intensive_benchmark(30)
        
        try:
            os.killpg(os.getpgid(tracer_process.pid), signal.SIGTERM)
            tracer_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(tracer_process.pid), signal.SIGKILL)
        time.sleep(15)  # Allow tracer to finish cleanup
        print("  Tracer stopped")
        
        self.monitor.stop_system_monitoring()
        
        tracer_results['system_metrics'] = {
            'cpu_usage': self.monitor.measurements['cpu_usage'].copy(),
            'memory_usage': self.monitor.measurements['memory_usage'].copy(),
            'disk_io': self.monitor.measurements['disk_io'].copy()
        }
        
        return tracer_results
    
    def analyze_overhead(self, baseline, with_tracer):
        """Analyze overhead by comparing baseline vs tracer measurements"""
        print("Analyzing overhead between baseline and tracer measurements...")
        analysis = {}
        
        # CPU overhead analysis
        if baseline['cpu_benchmark'] and with_tracer['cpu_benchmark']:
            cpu_base = baseline['cpu_benchmark']['checks_per_second']
            cpu_tracer = with_tracer['cpu_benchmark']['checks_per_second']
            cpu_overhead = ((cpu_base - cpu_tracer) / cpu_base) * 100
            
            analysis['cpu_slowdown'] = {
                'baseline_ops_per_sec': cpu_base,
                'tracer_ops_per_sec': cpu_tracer,
                'slowdown_percent': cpu_overhead
            }
        
        # I/O overhead analysis
        if baseline['io_benchmark'] and with_tracer['io_benchmark']:
            io_base = baseline['io_benchmark']['ops_per_second']
            io_tracer = with_tracer['io_benchmark']['ops_per_second']
            io_overhead = ((io_base - io_tracer) / io_base) * 100
            
            analysis['io_slowdown'] = {
                'baseline_ops_per_sec': io_base,
                'tracer_ops_per_sec': io_tracer,
                'slowdown_percent': io_overhead
            }
        
        # System CPU usage analysis
        base_cpu = [m['cpu_overall'] for m in baseline['system_metrics']['cpu_usage']]
        tracer_cpu = [m['cpu_overall'] for m in with_tracer['system_metrics']['cpu_usage']]
        
        if base_cpu and tracer_cpu:
            analysis['system_cpu_usage'] = {
                'baseline_avg': statistics.mean(base_cpu),
                'tracer_avg': statistics.mean(tracer_cpu),
                'overhead_percent': statistics.mean(tracer_cpu) - statistics.mean(base_cpu)
            }
        
        return analysis
    
    def run_full_analysis(self, duration=120):
        """Run complete overhead analysis"""
        print("Starting comprehensive tracer overhead analysis...")
        print(f"Total estimated time: {duration*2} seconds")

        # Run with tracer
        with_tracer = self.run_with_tracer_measurement(duration)
        
        # Run baseline
        baseline = self.run_baseline_measurement(duration)
        
        # Analyze results
        analysis = self.analyze_overhead(baseline, with_tracer)
        
        # Save all results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        results = {
            'timestamp': timestamp,
            'baseline': baseline,
            'with_tracer': with_tracer,
            'analysis': analysis
        }
        
        output_file = self.output_dir / f"overhead_analysis_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Generate report
        self.generate_report(analysis, self.output_dir / f"overhead_report_fix_{timestamp}.txt")
        
        print(f"Analysis complete! Results saved to {output_file}")
        return results
    
    def generate_report(self, analysis, output_file):
        with open(output_file, 'w') as f:
            f.write("VFS TRACER OVERHEAD ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            if 'cpu_slowdown' in analysis:
                cpu = analysis['cpu_slowdown']
                f.write(f"CPU-Intensive Application Slowdown:\n")
                f.write(f"  Baseline: {cpu['baseline_ops_per_sec']:.0f} ops/sec\n")
                f.write(f"  With Tracer: {cpu['tracer_ops_per_sec']:.0f} ops/sec\n")
                f.write(f"  Slowdown: {cpu['slowdown_percent']:.2f}%\n\n")
            
            if 'io_slowdown' in analysis:
                io = analysis['io_slowdown']
                f.write(f"I/O-Intensive Application Slowdown:\n")
                f.write(f"  Baseline: {io['baseline_ops_per_sec']:.0f} ops/sec\n")
                f.write(f"  With Tracer: {io['tracer_ops_per_sec']:.0f} ops/sec\n")
                f.write(f"  Slowdown: {io['slowdown_percent']:.2f}%\n\n")
            
            if 'system_cpu_usage' in analysis:
                sys_cpu = analysis['system_cpu_usage']
                f.write(f"System CPU Usage Impact:\n")
                f.write(f"  Baseline Average: {sys_cpu['baseline_avg']:.2f}%\n")
                f.write(f"  With Tracer Average: {sys_cpu['tracer_avg']:.2f}%\n")
                f.write(f"  Additional CPU Overhead: {sys_cpu['overhead_percent']:.2f}%\n\n")

if __name__ == "__main__":
    durations = [240, 300, 360, 420, 480, 540, 600]
    # durations = [12000]
    print("="*50 +" PARSER "+"="*50)
    for duration in durations:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tracer_cmd = f"sudo ./iotrcparse.py -o ./tmp/tracer_test_{timestamp}  -vfs ./result/IO_trace_analysis_20250623_094415/vfs_trace.log -blk ./result/IO_trace_analysis_20250623_094415/block_trace.log"

        analyzer = TracerOverheadAnalyzer(tracer_cmd)
        results = analyzer.run_full_analysis(duration=duration)
        if 'analysis' in results:
            analysis = results['analysis']
            print("+"*50)
            if 'cpu_slowdown' in analysis:
                print(f"CPU Slowdown: {analysis['cpu_slowdown']['slowdown_percent']:.2f}%")
            if 'io_slowdown' in analysis:
                print(f"I/O Slowdown: {analysis['io_slowdown']['slowdown_percent']:.2f}%")
            print("-"*50)
            
    print("="*50 +" TRACER "+"="*50)
    for duration in durations:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tracer_cmd = f"sudo ./iotrc.py -d {duration} -o /tmp/tracer_test_{timestamp}"

        analyzer = TracerOverheadAnalyzer(tracer_cmd)
        results = analyzer.run_full_analysis(duration=duration)
        if 'analysis' in results:
            analysis = results['analysis']
            print("+"*50)
            if 'cpu_slowdown' in analysis:
                print(f"CPU Slowdown: {analysis['cpu_slowdown']['slowdown_percent']:.2f}%")
            if 'io_slowdown' in analysis:
                print(f"I/O Slowdown: {analysis['io_slowdown']['slowdown_percent']:.2f}%")
            print("-"*50)
            